#TRUSTED 3b5950cb425e476f4612aedb6c220e246ebd210e9d2161ad4bc9ee30be1be9dcba4821326b11f0b11a7c91fba0fd5e6f6fbbbf4cc3285534165af956b80953fcea6d3c5a636d3e5eedb15747bc303264c07dc40a3c84247247fffc4e29b35cd9baca33c18330c8c0d11090891bd6a27b2a732d5653310fe1a00aba66b4918dc78e1b26fdc03e8d643f83c45ef1682da83bf780f05061032ff6ae47ec87fefc26979ed890545a901b0dc153a85fa1cd12b01a47ca0adf4c9542402b75caf908ed65570a567d70d49e16bdb5738f74d23a8b9fb7664ccd4452eff07f3e4cdbf883a2ff9b6a27594c3ae7c3f49f4890eae51268b16a0a5a9de84e3682f68adeaae2b43157a7d4db5622942486786df53ea9fc15d2ba07d227c02206378837ce9580ec4fed7959791523265352ca7c0e164b48f79111d46957a472abc3db707ae75d0f2e18af6667866ad66eac2e92eefc2ab487e192bd89e6751b79e67ac7186b8382db053addad4847d5d742e40123b5ee467c13d1bba095d3ca2e0accc4fc82c68f33e06a3dbdcd1d2a9982d4c183d5d6de5d33d495ffd0361c4d79ba16f8a9aa1c40f4dd39f145ed373000fdd1a17bf43d8a380263fd4b89c63241250a9a86051a6ff51fa77a646042589884402a5194b362a73ef343d680ee849b1a27542e878849f317dc8f2d761ae7873dc0151f1f9f1282bf90b6da7c710ff5a5811d5fa4
# -*- Fundamental -*-
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# ldap_func.inc
# Revision: 1.13
#



global_var _ldap_socket, _ldap_error, _msgid;


# LDAP request/response codes

LDAP_BIND_REQUEST      = 0x60;
LDAP_BIND_RESPONSE     = 0x61;
LDAP_SEARCH_REQUEST    = 0x63;
LDAP_SEARCH_RES_ENTRY  = 0x64;
LDAP_SEARCH_RES_DONE   = 0x65;
LDAP_MODIFY_REQUEST    = 0x66;
LDAP_MODIFY_RESPONSE   = 0x67;
LDAP_EXTENDED_REQUEST  = 0x77;
LDAP_EXTENDED_RESPONSE = 0x78;

# BER tags

LDAP_BOOLEAN_TAG         = 0x01;
LDAP_INTEGER_TAG         = 0x02;
LDAP_ENUMERATED_TAG      = 0x0a;
LDAP_SEQUENCE_TAG        = 0x30;
LDAP_STRING_SEQUENCE_TAG = 0x31;
LDAP_AUTHENTICATION_TAG  = 0x80;
LDAP_FILTER_TAG          = 0x87;

# LDAP internal error codes

LDAP_ERROR_SOCK_NO_DATA        = 1001;
LDAP_ERROR_SOCK_INVALID_TAG    = 1002;
LDAP_ERROR_INVALID_ID          = 1003;
LDAP_ERROR_DECODE              = 1004;

# LDAP result codes

LDAP_INVALID_CREDENTIALS = 0x31;

# LDAP filter codes

LDAP_FILTER_AND          = 0xa0;
LDAP_FILTER_OR           = 0xa1;
LDAP_FILTER_NOTEQUAL     = 0xa2;
LDAP_FILTER_EQUAL        = 0xa3;
LDAP_FILTER_SUBSTRING_OR = 0xa4;

# codes

MODIFY_DELETE   = 2;



#---------------------------------------------------------#
# Function    : mklist                                    #
# Description : Transforms arguments into a list. Replaces#
#               make_list to not destroy a list given as  #
#               argument.                                 #
#---------------------------------------------------------#

function mklist()
{
 local_var ret;
 local_var i, l;

 l = max_index (_FCT_ANON_ARGS);

 if (NASL_LEVEL >= 3000)
   ret  = fill_list(length:l, value:0);
 else
   ret = NULL;

 for (i=0 ; i<l ; i++)
   ret[i] = _FCT_ANON_ARGS[i];

 return ret;
}


#---------------------------------------------------------#
# Function    : ldap_init                                 #
# Description : Inits internal ldap data.                 #
#---------------------------------------------------------#

function ldap_init(socket)
{
 _msgid = 1;
 _ldap_socket = socket; 
}


#---------------------------------------------------------#
# Function    : ldap_get_last_error                       #
# Description : Gets last ldap-related error.             #
#---------------------------------------------------------#

function ldap_get_last_error()
{
 if (isnull(_ldap_error)) return NULL;
 else return _ldap_error;
}


#---------------------------------------------------------#
# Function    : ldap_set_error                            #
# Description : Sets ldap error and return NULL.          #
#---------------------------------------------------------#

function ldap_set_error()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 _ldap_error = l;
 return NULL;
}


#---------------------------------------------------------#
# Function    : der_encode_enumerated                     #
# Description : Encodes an enumerated value.              #
#---------------------------------------------------------#

function der_encode_enumerated(e)
{
 local_var val,j,tmp;

 if (isnull (e))
   return NULL;

 val[0] = e & 255;
 val[1] = (e>>8)  & 255;
# val[2] = (e>>16) & 255;
# val[3] = (e>>24) & 255;

 j = 3;
 while ((val[j] == 0) && (j != 0))
   j--;

 tmp = NULL;
 while (j != 0)
 {
  tmp += raw_string (val[j]);
  j--;
 }

 tmp += raw_string (val[j]);
 

 return der_encode(tag:LDAP_ENUMERATED_TAG, data:tmp);
}


#---------------------------------------------------------#
# Function    : der_encode_boolean                        #
# Description : Encodes a boolean.                        #
#---------------------------------------------------------#

function der_encode_boolean(b)
{
 return der_encode(tag:LDAP_BOOLEAN_TAG, data:raw_string(b));
}


#---------------------------------------------------------#
# Function    : der_encode_filter                         #
# Description : Encodes a filter.                         #
#---------------------------------------------------------#

function der_encode_filter(code, filter)
{
 if (isnull(code)) code = LDAP_FILTER_TAG;
 return der_encode(tag:code, data:filter);
}


#---------------------------------------------------------#
# Function    : ldap_request_sendrecv                     #
# Description : Sends ldap request and parse the response #
#---------------------------------------------------------#

function ldap_request_sendrecv(data)
{
 send(socket:_ldap_socket, data:data);
 return ldap_recv();
}

function ldap_recv_next()
{
 _msgid--;
 return ldap_recv();
}
#---------------------------------------------------------#
# Function    : ldap_recv                     	 	  #
# Description : Sends ldap request and parse the response #
#---------------------------------------------------------#
function ldap_recv()
{
 local_var buf, len, length_buf, msgid, id, data;

 buf = recv(socket:_ldap_socket, length:2, min:2);
 if (strlen(buf) < 2)
   return ldap_set_error(LDAP_ERROR_SOCK_NO_DATA);

 if (ord(buf[0]) != LDAP_SEQUENCE_TAG)
   return ldap_set_error(LDAP_ERROR_SOCK_INVALID_TAG);

 len = ord(buf[1]);

 if (len > 127)
 {
  len -= 128;
  length_buf = recv(socket:_ldap_socket, length:len, min:len);
  if (strlen(length_buf) < len)
    return ldap_set_error(LDAP_ERROR_SOCK_NO_DATA);

  len = integer (i:length_buf);
 }
 
 buf = recv(socket:_ldap_socket, length:len, min:len);
 if (strlen(buf) < len)
   return ldap_set_error(LDAP_ERROR_SOCK_NO_DATA);

 msgid = der_decode(data:buf, pos:0);
 if (isnull(msgid) || msgid[0] != LDAP_INTEGER_TAG)
   return ldap_set_error(LDAP_ERROR_DECODE);

 id = integer(i:msgid[1]);
 if (id != _msgid)
   return ldap_set_error(LDAP_ERROR_INVALID_ID);

 _msgid++;

 data = der_decode(data:buf, pos:msgid[2]);
 if (isnull(data))
   return ldap_set_error(LDAP_ERROR_DECODE);

 return data;
}


#---------------------------------------------------------#
# Function    : ldap_request                              #
# Description : Creates ldap request.                     #
#---------------------------------------------------------#

function ldap_request(code, data)
{
 local_var l;

 l = der_encode_int(i:_msgid) + der_encode(tag:code, data:data);

 return der_encode_list(list:l);
}


#---------------------------------------------------------#
# Function    : ldap_bind_request                         #
# Description : Creates ldap bind request.                #
#---------------------------------------------------------#

function ldap_bind_request(name, pass)
{
 local_var data, ret;
 if (isnull(name)) name = "";
 if (isnull(pass)) pass = "";

 data = 
	der_encode_int(i:3)                 +  # LDAP version
	der_encode_octet_string(string:name)  +  # name
	der_encode(tag:LDAP_AUTHENTICATION_TAG, data:pass);

 return ldap_request(code:LDAP_BIND_REQUEST, data:data);
}


#---------------------------------------------------------#
# Function    : ldap_parse_enumerated                     #
# Description : Parses encoded result field.              #
#---------------------------------------------------------#

function ldap_parse_enumerated(data)
{
 local_var tmp;

 tmp = der_parse_data(tag:LDAP_ENUMERATED_TAG, data:data);
 if (isnull(tmp))
   return ldap_set_error(LDAP_ERROR_DECODE);

 return integer(i:tmp);
}


#---------------------------------------------------------#
# Function    : ldap_parse_response                       #
# Description : Parses encoded response.                  #
#---------------------------------------------------------#

function ldap_parse_response(data)
{
 local_var list, result, dn, msg;

 list = der_parse_list(list:data);
 if (isnull(list) || list[0] < 3)
   return ldap_set_error(LDAP_ERROR_DECODE);

 result = ldap_parse_enumerated(data:list[1]);
 if (isnull(result))
   return ldap_set_error(LDAP_ERROR_DECODE);

 dn = der_parse_octet_string(string:list[2]);
 if (isnull(result))
   return ldap_set_error(LDAP_ERROR_DECODE);

 msg = der_parse_octet_string(string:list[3]);
 if (isnull(result))
   return ldap_set_error(LDAP_ERROR_DECODE);

 return mklist(result, dn, msg);
}


#---------------------------------------------------------#
# Function    : ldap_parse_bind_response                  #
# Description : Parses encoded bind response.             #
#---------------------------------------------------------#

function ldap_parse_bind_response(data)
{
 return ldap_parse_response(data:data);
}


#---------------------------------------------------------#
# Function    : ldap_parse_modify_response                #
# Description : Parses encoded modify response.           #
#---------------------------------------------------------#

function ldap_parse_modify_response(data)
{
 return ldap_parse_response(data:data);
}


#---------------------------------------------------------#
# Function    : ldap_modify_request                       #
# Description : Creates ldap modify request.              #
#---------------------------------------------------------#

function ldap_modify_request(object, operation, data)
{
 local_var item, mlist, req, list;

 item = 
	der_encode_int(i:operation) +
	der_encode_list(list:data);

 mlist = der_encode_list(list:item); # ItemList

 req = 
	der_encode_octet_string (string:object) +
	der_encode_list(list:mlist);


 return ldap_request(code:LDAP_MODIFY_REQUEST, data:req);
}


#---------------------------------------------------------#
# Function    : ldap_search_request                       #
# Description : Creates ldap search request.              #
#---------------------------------------------------------#

function ldap_search_request(object, filter, scope, attributes)
{
 local_var req, attr, attrstr, items, filterstr, item;

 # Convert the attributes to a list if it isn't one already
 if ( isnull(attributes)) attributes = make_list("");
 else
 {
   if (typeof(attributes) != 'array')
     attributes = make_list(attributes);
 }
 if ( isnull(scope) ) scope = 0;

 attrstr = "";
 foreach attr (attributes)
 {
   attrstr = attrstr + der_encode_octet_string(string:attr);
 }

 # Construct the filter if it is passed in as a list
 if (isnull(filter)) filter = '';
 filterstr = '';
 if (typeof(filter) != 'array') 
 {
   filterstr = der_encode_filter(filter:filter);
 }
 else
 {
   item = filter[0];
   if (!isnull(item['left']) && !isnull(item['conditional']) && !isnull(item['right']))
   {
     filterstr += der_encode_octet_string(string:item['left']);
     filterstr += der_encode_octet_string(string:item['right']);
     filterstr = der_encode_filter(code:item['conditional'], filter:filterstr);
   }
   else filterstr = der_encode_filter(filter:'objectClass');
 }

 req = 
	der_encode_octet_string (string:object) +
        der_encode_enumerated(e:scope) +
        der_encode_enumerated(e:0) +
        der_encode_int(i:0) +
        der_encode_int(i:0) +
        der_encode_boolean(b:FALSE) +
        filterstr +
	der_encode_list(list:attrstr);


 return ldap_request(code:LDAP_SEARCH_REQUEST, data:req);
}

#---------------------------------------------------------#
# Function    : ldap_parse_search_object_name             #
# Description : Parses encoded search entry.              #
#---------------------------------------------------------#

function ldap_parse_search_object_name(data)
{
 local_var list, object, ret, i, tlist, type, values, vlist, j;

 list = der_parse_list(list:data);
 if (isnull(list) || list[0] < 2)
   return ldap_set_error(LDAP_ERROR_DECODE);

 object = der_parse_octet_string(string:list[1]);
 if ( isnull(object) ) 
   return ldap_set_error(LDAP_ERROR_DECODE);
 
 return object;
}


#---------------------------------------------------------#
# Function    : ldap_parse_search_entry                   #
# Description : Parses encoded search entry.              #
#---------------------------------------------------------#

function ldap_parse_search_entry(data)
{
 local_var list, object, ret, i, tlist, type, values, vlist, j;

 list = der_parse_list(list:data);
 if (isnull(list) || list[0] < 2)
   return ldap_set_error(LDAP_ERROR_DECODE);

 object = der_parse_octet_string(string:list[1]);

 list = der_parse_data(tag:LDAP_SEQUENCE_TAG, data:list[2]);
 if (isnull(list))
   return ldap_set_error(LDAP_ERROR_DECODE);

 list = der_parse_list(list:list);
 if (isnull(list))
   return ldap_set_error(LDAP_ERROR_DECODE);

 ret = NULL;
 for (i=1; i<=list[0]; i++)
 {
  tlist = der_parse_data(tag:LDAP_SEQUENCE_TAG, data:list[i]);
  if (isnull(tlist))
    return ldap_set_error(LDAP_ERROR_DECODE);

  tlist = der_parse_list(list:tlist);
  if (isnull(tlist) || tlist[0] != 2)
    return ldap_set_error(LDAP_ERROR_DECODE);

  type = der_parse_octet_string(string:tlist[1]);
  values = der_parse_data(tag:LDAP_STRING_SEQUENCE_TAG, data:tlist[2]);
  if (isnull(tlist))
    return ldap_set_error(LDAP_ERROR_DECODE);

  values = der_parse_list(list:values);
  if (isnull(values))
    return ldap_set_error(LDAP_ERROR_DECODE);

  vlist = NULL;
  for (j=1; j<=values[0]; j++) 
    vlist[j-1] = der_parse_octet_string(string:values[j]);

  ret[i-1] = mklist(type, vlist);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : ldap_extended_request                     #
# Description : Creates an ldap extended request.         #
#---------------------------------------------------------#

function ldap_extended_request(oid, val)
{
  local_var req;

  # nb: the args are octet strings that that must use a 
  #     context-specific rather than universal class.
  req = der_encode(tag:(0x04|0x80), data:oid);
  if (!isnull(val)) req += der_encode(tag:(0x04|0x80), data:val);

  return ldap_request(code:LDAP_EXTENDED_REQUEST, data:req);
}


#---------------------------------------------------------#
# Function    : ldap_parse_extended_response              #
# Description : Parses encoded extended response.         #
#---------------------------------------------------------#

function ldap_parse_extended_response(data)
{
  local_var list, result, dn, msg, respName, resp, val;

  list = der_parse_list(list:data);
  if (isnull(list) || list[0] < 3)
    return ldap_set_error(LDAP_ERROR_DECODE);

  result = ldap_parse_enumerated(data:list[1]);
  if (isnull(result))
    return ldap_set_error(LDAP_ERROR_DECODE);

  if (substr_at_offset(str:list[2], blob:'\x04\x00', offset:0)) dn = "";
  else
  {
    dn = der_parse_octet_string(string:list[2]);
    if (isnull(dn))
      return ldap_set_error(LDAP_ERROR_DECODE);
  }

  if (substr_at_offset(str:list[3], blob:'\x04\x00', offset:0)) msg = "";
  else
  {
    msg = der_parse_octet_string(string:list[3]);
    if (isnull(msg))
      return ldap_set_error(LDAP_ERROR_DECODE);
  }

  if (list[0] > 3)
  {
    if (substr_at_offset(str:list[4], blob:'\x04\x00', offset:0)) respName = "";
    else
    {
      val = der_decode(data:list[4]);
      # IBM Tivoli Directory Server uses tag 0x8a for respName
      if (
        !isnull(val) &&
        (val[0] == 0x8a || val[0] == 0x4)
        ) respName = val[1];
      else return ldap_set_error(LDAP_ERROR_DECODE);
    }
  }
  else respName = "";

  if (list[0] > 4)
  {
    if (substr_at_offset(str:list[5], blob:'\x04\x00', offset:0)) resp = "";
    else
    {
      val = der_decode(data:list[5]);
      # IBM Tivoli Directory Server uses tag 0x8b for resp
      if (
        !isnull(val) &&
        (val[0] == 0x8b || val[0] == 0x4)
        ) resp = val[1];
      else return ldap_set_error(LDAP_ERROR_DECODE);
    }
  }
  else resp = "";

  return mklist(result, dn, msg, respName, resp);
}


#----------------------------------------------------------------#
# Function    : ldap_starttls                                    #
# Description : Sends a START TLS extended request to an open    #
#                 socket.                                        #
# Inputs      : 'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (ldap_starttls(encaps:encaps))                #
#               {                                                #
#                 search = ldap_search_request(...               #
#----------------------------------------------------------------#
function ldap_starttls(encaps)
{
  local_var res, xres;

  res = ldap_request_sendrecv(
    data:ldap_extended_request(oid:'1.3.6.1.4.1.1466.20037')
  );
  if (
    isnull(res) ||
    res[0] != LDAP_EXTENDED_RESPONSE
  ) return NULL;

  xres = ldap_parse_extended_response(data:res[1]);
  if (isnull(xres) || xres[0] != 0) return NULL;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:_ldap_socket, transport:encaps);
  }
  return _ldap_socket;
}

#----------------------------------------------------------------#
# Function    : ldap_extract_dc                                  #
# Description : Extracts the domain information from the         #
#               namingContext                                    #
# Inputs      : 'namingcontext' => The namingContext to parse    #
# Return      : An array with the domain context as well as the  #
#               domain to use in a bind request                  #
#----------------------------------------------------------------#
function ldap_extract_dc(namingcontext)
{
  local_var ret, i, obj, domain, item;

  if (isnull(namingcontext)) return NULL;

  obj = '';
  domain = '';
  namingcontext = split(namingcontext, sep:',');
  for (i=0; i<max_index(namingcontext); i++)
  {
    item = tolower(namingcontext[i]);
    if ('dc=' >< item && ('dc=domaindnszones' >!< item && 'dc=forestdnszones' >!< item))
    {
      obj += namingcontext[i];
      namingcontext[i] = namingcontext[i] - 'DC=';
      namingcontext[i] = namingcontext[i] - ',';
      domain += namingcontext[i];
      if (i < max_index(namingcontext) -1)
      {
        domain += '.';
      }
    }
  }
  ret = make_array('obj', obj, 'domain', domain);
  return ret;
}
