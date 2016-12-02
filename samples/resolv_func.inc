#TRUSTED 1b877632f2bba0381ce0a1d806f7f185b4c19cbc6eedbf1cbf2989f7a89cbedfd9eb749dcdd51f9c5ea612e9017c68cf687284178ee89806a28cc7ece56b4fb6fa81b98131f224944e983c049a9dcf0254faada20b175b7115a54cec42bb9e53757e87c60ea9825b4772ea8c789e1ee0bb2bdbd965bc8ae5474eb8a7e26af059ba026062bce7a4dd7c6cb6bb1d3b3299ab7c62018f7799327f712e337c0c02e655f8da5874c5f6b2375327e9b7ad44aaf073538b3673bceccbd21904b00003c6289b8a14a37dcb4cef362d799be78755060852f087807855368da618384d7921158f721df1fcfd966b1e541b199a4873c2a68181f40c2e04b509f9724edde23ccd200c7cf2403c2640e4e0f98a7ab4809ece938936d58c0723bb65e31eec4533ad1612f49d23f1a4b1680e85e1da7a595b8f0489ab558212867bf0e3986116e49fecacbe92b6836455aeae8869c2bacc01f375caf5a917e6ff290ed602696857dddc57e5a7aeee326c32293e4a431c2a05bffe32ba6812b96440a2e9cdfedf1c51fd1c7ad85093f10c07e3bcf83f00509dee2c18c0e83af1d121ec54ab885bf9275d63f0d4abee3fc5168c9af6cc5617c3263bdb27c6e0242dba61f8c6a4dfd073f59ab6033779f1c44a9f912f35105076341e801ce0c8b4e5b30c9853b80e5b22b960ace4c0931bd8d9561242d00986589a65c1ac55fda80ef6b742d291d5f6
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# resolv_func.inc
#
# Revision: 1.7
#

include ("spad_log_func.inc");
include ("obj.inc");

function is_host_ip(name)
{
 if (":" >< name || ereg(string:name, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") )
   return TRUE;

 return FALSE;
}


function fqdn_resolv(name, ipv6, fqdn)
{
  local_var len;

  # Check to make sure we are not tryign to resolv an IP
  if ( is_host_ip(name:name) ) return make_list(name);

  # Adds a "." at the end of the name to make sure it is a FQDN
  if ( fqdn )
  {
   len = strlen(name);
   if ( len > 0 && name[len-1] != '.' )
     name = name + ".";
  }

  resolv = resolv(name:name, ipv6:ipv6);

  if(get_kb_item("global_settings/enable_plugin_debugging"))
  {
    msg = '[fqdn_resolv] Resolving the IP for the following FQDN:\n' +
          '\tName : ' + name + '\n' +
          '\tIP : ' + obj_rep(resolv) + '\n';

    log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
    spad_log(message:msg,name:log_name);
  }

  return resolv;
}

function cmp_addr_v(a, b)
{
  local_var am, bm, ai, bi;

  am = max_index(a);
  bm = max_index(b);

  for (ai = 0; ai < am; ai ++)
  {
    for (bi = 0; bi < bm; bi ++)
    {
      if(get_kb_item("global_settings/enable_plugin_debugging"))
      {
        msg = '[cmp_addr_v] Comparing the following IPs:\n' +
              '\tIP 1 : ' + a[ai] + '\n' +
              '\tIP 2 : ' + b[bi] + '\n';

        log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
        spad_log(message:msg,name:log_name);
      }

      if (a[ai] == b[bi])
        return 1;
    }
  }
  return 0;
}

global_var _target_ip_resolv, _target_name_resolv;

# If b=NULL, compare a with the target
function is_same_host(a, b, fqdn)
{
  local_var v1, v2, b1, b2, ipv6;

  if(get_kb_item("global_settings/enable_plugin_debugging"))
  {
    msg = '[is_same_host] Comparing the following two hosts:\n' +
          '\tHost 1 : ' + a + '\n' +
          '\tHost 2 : ' + b + '\n';

    log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
    spad_log(message:msg,name:log_name);
  }

  if (a == b) return 1;

  if (isnull(b))
  {
    if (isnull(a))
    {
      display("ERR: is_same_host: missing arguments 'a' & 'b'\n");
      return NULL;
    }
    b1 = get_host_ip();
    b2 = get_host_name();

    if(get_kb_item("global_settings/enable_plugin_debugging"))
    {
      msg = 'We got the following when getting the host information for comparison:\n' +
            '\tHost IP : ' + b1 + '\n' +
            '\tHost Name : ' + b2 + '\n';

      log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
      spad_log(message:msg,name:log_name);
    }

    if (a == b1 || tolower(a) == tolower(b2)) return 1;
    if (! defined_func("resolv")) return 0;

    if (isnull(_target_ip_resolv))
    {
      _target_ip_resolv = fqdn_resolv(name: b1, ipv6: TARGET_IS_IPV6, fqdn: FALSE);
      if (isnull(_target_ip_resolv)) return NULL;
    }
    v2 = fqdn_resolv(name: a, ipv6: TARGET_IS_IPV6, fqdn: fqdn);
    if (isnull(v2)) return NULL;
    if (cmp_addr_v(a: _target_ip_resolv, b: v2)) return 1;

    if (b1 != b2)
    {
      if (isnull(_target_name_resolv))
      {
        _target_name_resolv = fqdn_resolv(name: b2, ipv6: TARGET_IS_IPV6, fqdn: fqdn);
        if (isnull(_target_name_resolv)) return NULL;
      }
      if (cmp_addr_v(a: _target_name_resolv, b: v2)) return 1;
    }

    return 0;
  }

  if (! defined_func("resolv")) return 0;

  for (ipv6 = 0; ipv6 <= 1; ipv6 ++)
  {
    v1 = fqdn_resolv(name: a, ipv6: ipv6, fqdn: fqdn);
    if (isnull(v1)) continue;
    v2 = fqdn_resolv(name: b, ipv6: ipv6, fqdn: fqdn);
    if (isnull(v2)) continue;

    if (cmp_addr_v(a: v1, b: v2)) return 1;
  }

  return 0;
}
