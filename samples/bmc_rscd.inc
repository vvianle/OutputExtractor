#TRUSTED 22dda1a2b73eb7ce08722d075ce0c894c4b80c9393742117dec473cea3a844f495d7579e1c7148e002d2aabad17f174e8bebb951ec4f4d3194296422d4d1238e8f763d811b7dfbafcaa3d66822453c62c2a0bebf9cf5e6fc463fa95d4c922ac5fd412648f13adc19a9980f5ac4e9a40abc3bd341dfb7e929c3d3783548028e673e28777f51d258e855e490a6bc7d286329f12b7964daef6f7ec6b64bc9f4cc24c08aa7870aeab8d42c9e4d76418e41a04e5cdb63597063ce31e50d83028f7bd2b1396d8cfe7afdcb1035012f7570eb45011b72c72a22ce1c679b21079aa032c01bd0cc103fa397aa48c340cf30736b53250ffd6f050970e4474888b54f852b492c86ed1ac38749b23e059c9651fd50e091ad848c25db5b36ba6f812646368ff2e69ca4e2f061a1ac394ea031b705ac0f8b7369eef0aac3fb61a5aa078abe284dedbbc873adacbb7a1e85cb0ef4c4f3aa0194713503c6c062ed539684d07050c17476ac5281a600b4ad0f7e4de505e04f88e76957c7dfc7708ec319372ad9c52308996fcf60a80b8fd8365f64abec3e787542afe7c1398bcec0fb6598f9a91d9341bccb1c74a2d85ee53397fd2176dc4ffc09a6fbdbff378d8cb4a0bc6a7a88882fd1efb9461a9b0952a9ece35da5d6ad04fe91e45315163b9243a00b02ee1731fe263f006f1d88a508a909766842a5642a92ae2c245de2e77db51a3ea694216b

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision
#

##
# Connects to port and sends the upgrade message and
# then establishes an SSL Connection. This function
# modifies the global 'soc' object.
#
# @param type the protocol type ('TLS' or 'TLSRPC')
# @param port the port to connect to
# @return a new sock with the SSL connection establish
##
function rscd_connect(type, port)
{
  local_var soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_NOT_LISTEN, "BMC RSCD", port);

  # The protocol requires an upgrade string to indicate
  # network shell or XML RPC.
  send(socket:soc, data:type);
  soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);
  if (isnull(soc)) audit(AUDIT_SSL_FAIL, "TLS", port);

  return soc;
}

##
# Reads in a response from the server. The first four bytes
# indicates how long the message that follows will be.
#
# @param soc the socket to receive drom
# @return the message received from the server
##
function get_netsh_response(soc)
{
  local_var length;
  length = recv(socket:soc, length:4, min:4);
  length = getdword(blob:length, pos:0);
  return recv(socket:soc, length:int(length), min:int(length));
}

##
# Sends data to the server. Appends the provided message
# to the length frame.
#
# @param soc the soc to send on
# @param data the data to send
##
function send_netsh_data(soc, data)
{
  data = '\x00\x00\x00' + raw_string(strlen(data)) + data;
  send(socket:soc, data:data);
}

##
# Frames the payload up into an HTTP POST request
#
# @param payload the XMLRPC payload to send
# @param soc the socket to send on
# @param port the port we are sending to
##
function send_xmlrpc(payload, soc, port)
{
  local_var request =
    'POST /xmlrpc HTTP/1.1\r\n' +
    'Host: ' + get_host_ip() + ':' + port + '\r\n' +
    'User-Agent: Nessus\r\n' +
    'Content-Type: text/xml\r\n' +
    'Content-Length: ' + len(payload) + '\r\n\r\n' + payload;
  send(socket:soc, data:request);
}

##
# Sends an intro message in the XML RPC format. We attempt to
# introduce ourselves as the fake user "Nessus Scan". We also
# parse the response to ensure that the responder is RSCD.
#
# @param soc the socket connected to rscd
# @port port the port we are sending to
# @return the servers response
##
function send_xml_intro(soc, port)
{
  local_var payload, resp;

  # Send an "intro" request - which is basically "I'm this user"
  payload = '<?xml version="1.0" encoding="UTF-8"?>\n' +
   '<methodCall>\n' +
   '  <methodName>RemoteServer.intro</methodName>\n' + 
   '    <params>\n' +
   '      <param><value>1</value></param>\n' +
   '      <param><value>2</value></param>\n' + 
   '      <param><value>0;0;b;Nessus Scan;2;CM;-;-;0;-;1;1;b;Nessus Scan;CP1252;</value></param>\n' +
   '      <param><value>8</value></param>\n' +
   '    </params>\n' +
   '</methodCall>';
  send_xmlrpc(payload:payload, soc:soc, port:port);

  resp = recv(socket:soc, length:1024);
  if (isnull(resp))
  {
    close(soc);
    audit(AUDIT_RESP_BAD, port);
  }
  else if ("Server: XMLRPC++" >!< resp)
  {
    close(soc);
    audit(AUDIT_NOT_DETECT, "BMC RSCD", port);
  }

  return resp;
}

function decompress_payload(resp)
{
  local_var end_of_header, compressed_data_start;
  if (isnull(resp) || 'Content-Encoding: gzip\r\n' >!< resp || '\r\n\r\n' >!< resp) return NULL;

  # decompress the payload
  end_of_header = strstr(resp, '\r\n\r\n');
  compressed_data_start = substr(end_of_header, 4);
  return gunzip(compressed_data_start);
}
