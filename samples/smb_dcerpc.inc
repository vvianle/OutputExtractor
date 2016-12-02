#TRUSTED 16463fd55ae27c27d5e69a8da98838612d01fed76f61dcda638b445106e795a1ba7c2ab6fc0abff670d159689a2115b46c4295a5c3c47f3a9e02517970264f2b1260b877a75f0d6f7250436173bd70300be279df03d5d28cc8dcc95608310d95febadf8ece7f4db05ec8a31ab95cb40d57dc0376ea55e1aa3a162a4855174c56ca7ae4823e526b0b906d41e40290e758d6f047af13b61e4b75678577e1545ad7e47def69a7555f19ae95a16fd89287ed4d898b79dbf973b4e20a7b2ee63543e8a9129c4f5b5d5b9efa122b13515d6ff1693adea116699f6210c5bec0de3548eba1896a07e2fe3b841f9752329ab61525274fc1cd642959e35a959f61dc5cebe8bfc5489fab0988a5c332e32f8284489aeb9a68ca81d806a7a9f4af1db00e8ba505807bdf28952860c51a55d5bf01695a2a754fff98b28ba4a6b24142f132bfbd939ba146971dfc1137a46d99d4cc2b5db9c17051c4cd4a1e2ac22d9bc4854c00855ed1df3693499a81568a15d6b3c10220083d2fc488fa1130fcb8bb341eeb2e02aee1db4f78ae82e504d00e7af01e930ea27c3f75e37dc02a317c48b93ee4bc23fb1f1824e5e405ca4266fee756433cf030e5e826a066f06e081514aa093907252d1177f6bcd04a9702fd4f6fc1dd967b35bdac268210f4d2af66c790bbd91418ece96029124cba3804412424939eef56b7c6ada7da3b7da60f33973e92bb92
#------------------------------------------------------------------------------
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smb_dcerpc.inc
# Revision: 1.11
#


function dce_rpc (type,cid,data,flags,auth_header,auth_data)
{
 local_var packet, flag, alen, flen;

 if (isnull(flags))
   flag = 3; # FIRST fragment, LAST fragment
 else
   flag = flags;


 if (!isnull(auth_data))
 {
  alen = strlen(auth_data);
  flen = 16 + strlen(data) + alen + strlen (auth_header);
 }
 else
 {
  alen = 0;
  flen = 16 + strlen(data);
  auth_data = auth_header = NULL;
 }

 packet = raw_byte (b:5) +                # version
          raw_byte (b:0) +                # version (minor)
	  raw_byte (b:type) +             # packet type
	  raw_byte (b:flag) +             # packet flags
	  raw_dword (d:16) +              # data representation (little-endian/ascii)
	  raw_word (w:flen) +             # Frag length
	  raw_word (w:alen) +             # auth length
	  raw_dword (d:cid) +             # caller ID
	  data +
          auth_header +
          auth_data;
 
 return packet;
}


function dce_rpc_ntlmssp_header (code)
{
 local_var header;

 header =
	  raw_byte (b:10)   +       # Auth type: NTLMSSP
	  raw_byte (b:code) +       # Auth level
	  raw_byte (b:0)    +       # Auth pad length: 0
	  raw_byte (b:0)    +       # Reserved
	  raw_dword (d:0);          # Auth context id (to randomize for multiple sessions)

 return header;
}


function dce_rpc_bind (cid, uuid, vers, auth)
{
 local_var packet, auth_header, auth_data;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) +       # Max recv Frag
	  raw_dword (d:0)   +       # Assoc group
	  raw_dword (d:1)   +       # Num context items
	  raw_word (w:0)    +       # Context ID
	  raw_word (w:1)    +       # num trans item
	  encode_uuid (uuid:uuid) + # Interface uuid
	  raw_word (w:vers)    +       # interface version
	  raw_word (w:0)    +       # interface version (minor)
	  encode_uuid (uuid:"8a885d04-1ceb-11c9-9fe8-08002b104860") +
	  raw_dword (d:2) ;         # syntax version

 if (!isnull(auth) && (auth == TRUE))
 {
  auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
  auth_data = raw_ntlmssp_negotiate();
 }
 else
 {
  auth_data = auth_header = NULL;
 }

 return dce_rpc (type:DCE_RPC_BIND, cid:cid, data:packet, auth_header:auth_header, auth_data:auth_data);
}



function dce_rpc_parse_bind_ack (data, auth, cid)
{
 local_var len, res, ret, ntlmssp, pos, pad_len;

 if (strlen (data) < 26)
   return NULL;
 len = get_word (blob:data, pos:24);
 if ((len%2) != 0)
   len += 1; # byte padding

 if (strlen (data) < (26+len+4))
   return NULL;

 res = get_word (blob:data, pos:26+len+4); # error code

 # if no auth, returns the value for compatibility
 if (isnull(auth) || (auth == FALSE))
   return res;

 ret = NULL;
 ret[0] = res;

 if (res != 0)
   return ret;

 ret[1] = get_word (blob:data, pos:20);  # association group

 if (strlen (data) < 26+len+4+32)
   return NULL;

 pos = 26+len+4+26;
 pad_len = get_byte (blob:data, pos:pos);

 pos += 6 + pad_len;

 ntlmssp = substr(data, pos, strlen(data-1));

 ntlmssp = raw_ntlmssp_parse_challenge (data:ntlmssp);

 if (isnull(ntlmssp))
   return NULL;

 ret[2] = ntlmssp[0];
 ret[3] = cid;

 return ret;
}

function dce_rpc_alter_context (cid, uuid, vers)
{
 local_var packet, auth_header, auth_data;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) +       # Max recv Frag
	  raw_dword (d:0)   +       # Assoc group
	  raw_dword (d:1)   +       # Num context items
	  raw_word (w:0)    +       # Context ID
	  raw_word (w:1)    +       # num trans item
	  encode_uuid (uuid:uuid) + # Interface uuid
	  raw_word (w:vers)    +       # interface version
	  raw_word (w:0)    +       # interface version (minor)
	  encode_uuid (uuid:"8a885d04-1ceb-11c9-9fe8-08002b104860") +
	  raw_dword (d:2) ;         # syntax version

 auth_data = auth_header = NULL;

  auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
  auth_data = raw_dword (d:1) + crap(data:raw_string(0), length:12);

 return dce_rpc (type:DCE_RPC_ALTER, cid:cid, data:packet, auth_header:auth_header, auth_data:auth_data);
}


function dce_rpc_auth3 (cid, login, password, domain, challenge)
{
 local_var packet, auth_header, auth_data;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) ;       # Max recv Frag

 auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
 auth_data = raw_ntlmssp_auth_securityblob (password:password, login:login, domain:domain, challenge:challenge);

 return dce_rpc (type:DCE_RPC_AUTH3, cid:cid, data:packet, auth_header:auth_header, auth_data:auth_data[0]);
}


function dce_rpc_connect (socket, cid, uuid, vers, login, password, domain)
{
 local_var ret, resp, pass, name, dom;

 ret = dce_rpc_bind(cid:cid, uuid:uuid, vers:vers, auth:TRUE);

 send (socket:socket, data:ret);
 resp = recv (socket:socket, length:4096);

 if (!resp)
   return NULL;

 resp = dce_rpc_parse_bind_ack (data:resp, cid:cid, auth:TRUE);
 if (isnull (resp))
   return NULL;

 pass = cstring (string:password, _null:1);
 name = cstring (string:login, _null:1);
 dom = cstring (string:domain, _null:1);  

 ret = dce_rpc_auth3 (cid:cid, login:name, password:pass, domain:dom, challenge:resp[2]);
 send (socket:socket, data:ret);

 return resp;
}



function dce_rpc_request (code, data, flags, id, auth, type)
{
 local_var packet, cid, auth_header, auth_data;

 if (!isnull(auth) && (auth == TRUE))
 {
  auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
  auth_data = raw_dword (d:1) + crap(data:raw_string(0), length:12);
  cid = id;
 }
 else
 {
  if (isnull(id))
    cid = session_get_cid();
  else
    cid = id;

  auth_header = auth_data = NULL;
 }

 # this is an edge case where we wanted to control the type field
 if (isnull(type)) type = DCE_RPC_REQUEST;

 packet = raw_dword (d:strlen(data))  +       # Alloc hint
          raw_word (w:0)              +       # Context ID
	  raw_word (w:code)           +       # Opnum
          data;
 
 return dce_rpc (type:type, cid:cid, data:packet, flags:flags, auth_header:auth_header, auth_data:auth_data);
}



function dce_rpc_sendrecv_request (socket, id, code, data, flags)
{
 local_var req, ret;

 req = dce_rpc_request (code:code, data:data, flags:flags, id:id, auth:dcerpc_auth);
 send (socket:socket, data:req);
 ret = recv (socket:socket, length:4096);

 return ret;
}


function dce_rpc_pipe_request (fid, code, data, type)
{
 local_var tmp, rep, len, flag, ret, offset, cid, dat, size, data_len;

 size = session_get_server_max_size() - 110;
 cid = session_get_cid();
 offset = 0;
 data_len = strlen(data);

 if (data_len > size)
 {
   flag = 1; # FIRST fragment
   tmp = substr (data, 0, size-1);
   len = size;
 }
 else
 {
   flag = 3; # FIRST fragment, LAST fragment
   tmp = data;
   len = data_len;
 }

 while (len < data_len)
 {
  ret = smb_write_and_x (fid:fid, offset:offset, mode:WRITE_START, data:dce_rpc_request (code:code, data:tmp, flags:flag, id:cid));
  if (isnull (ret) || (ret != 1))
    return NULL;

  offset += strlen(tmp);

  if ((len + size) < data_len)
  {
   flag = 0;
   tmp = substr (data, len, len+size-1);
   len += size;
  }
  else
  {
   flag = 2;
   tmp = substr (data, len, data_len-1);
   break;
  }
 }

 ret = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:code, data:tmp, flags:flag, id:cid, type:type));
 if (isnull (ret))
   return NULL;

 return ret;
}


function dce_rpc_parse_response (fid, data)
{
 local_var resp, flag, len, alloc, tmp, dat, type;

 if (strlen (data) < 24)
   return NULL;
   
 type = get_byte (blob:data, pos:2);

 # Fault -> return NULL
 if (type == 3)
   return NULL;

 flag = get_byte (blob:data, pos:3);
 len = get_word (blob:data, pos:8) - 24;
 alloc = get_dword (blob:data, pos:16);

 

 if (strlen (data) < (24 + len))
   return NULL;
   
 resp = substr (data, 24, 24 + len - 1);

 # If it is not the last dce_rpc packet we continue to read
 while (!(flag & 2))
 {
  # we read only 1000 bytes at a time
  tmp = smb_read_and_x (fid:fid, offset:0, length:1024);
  if (strlen (tmp) < 24)
    return NULL;

  flag = get_byte (blob:tmp, pos:3);
  len = get_word (blob:tmp, pos:8);
  alloc = get_dword (blob:tmp, pos:16);

  while (strlen (tmp) < len)
  {
   dat = smb_read_and_x (fid:fid, offset:0, length:1024);
   if (!dat)
     return NULL;
   tmp += dat;
  }
  
  resp += substr (tmp, 24, 24 + len - 1);
 }

 return resp;
}


function bind_pipe (pipe, uuid, vers)
{
 local_var fid, ret, data;

 ret = smb_create_and_x (name:pipe,
                         desired_access:FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                         flags_attributes:0,
                         share_mode:0,
                         create_disposition:OPEN_EXISTING,
                         create_options:0x00400040);
 if (isnull(ret))
   return NULL;
 
 fid = ret[0];

 ret = smb_write_and_x (fid:fid, offset:0, mode:WRITE_START, data:dce_rpc_bind(cid:session_get_cid(), uuid:uuid, vers:vers));
 if (isnull (ret) || (ret != 1))
   return NULL;

 data = smb_read_and_x (fid:fid, offset:0, length:1024);
 if (!data)
   return NULL;
 
 ret = dce_rpc_parse_bind_ack (data:data);
 if (isnull (ret) || (ret != 0))
   return NULL;

 return fid;
}


