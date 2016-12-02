#TRUSTED 279b830677f48e10f9ec6b331ff4f42699f0377cfdbb13e5494184fa75e3dcd7f5144923711e47bd876066e7b64e57ef4c173d7bceff8fd0eb72b62d51b463fbdd91bcd16bdfcb17d0ac1c938d5be5c0bcf6b31057cf8eecb6041d2273f89cd32901e76856f1afcf23062eb495b729685efbe6b56dfd90e8f0e1167aab801bcd6b56ad780bb53fe88393f196251a3a68f3d7bfe3589162abbfce804508e2fbc9f312fd34832520839f5a9ffdea8f6b2c2ce3aba57675a0680a33040d13ead58c60456bf23f2e578fefc0cbd7afdb56dc884d101f2463b253ed085e0c303404ae869b8eb5de093091ae2391ea0bf481715b0988852938b2173b3da2c3ecded80fa709ac5ccb3f8f631ef4548d8b7ae5371e65692a81a385cf1a2cf426df0b808c2271d60921a622fb62293e1b35942f1cf49ffd6557e9aa17a811d5245de4059f48d2f4dac32d8dfda1cf8934e0dfb00836a7f84a871063a04e305f138c46434f3f44c0f9ae81554bf731c975c08e84492e23d9b962630e9c8224b11c0c09776553511d8ddad159193d570dbd2c3d55edcc88c4730f86b2fc810bc6618f8c002ffc6e42f53f095b3f79173b78cb2c339b4222dc3ab20142bab49681d9dc7eb21413cfa5d62a66ec6b324782fba25399224d0897146c3c392ff6c38ab1f4e371c0b6aa0232442f88e82f4834e40c94caaf5c3e3a962e7717ffe6f55e91e4dcc284
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# hostlevel_funcs.inc
#
# Revision: 1.15
#

global_var report_verbosity, port_g, login, pass;
global_var	info_t, sock_g, sep, c;

INFO_LOCAL  = 1;
INFO_SSH    = 2;
INFO_RSH    = 3;
INFO_REXEC  = 4;
INFO_RLOGIN = 5;
INFO_TELNET = 6;

# Error codes
HLF_OK       =  0;  # No error
HLF_MISMATCH = -1;  # Argument no./template mismatch.
HLF_INVALID  = -2;  # Invalid characters in argument(s)
HLF_NO_ARG   = -3;  # An argument is missing.

##
# Open a telnet connection
#
# @param port telnet port
# @param login user to login with
# @param pass password to login with
#
# @return Returns socket if successful, otherwise returns NULL
##
function telnet_open_cnx(port, login, pass)
{
 local_var	s, res;
 local_var	ps;

 if ( ! get_port_state(port) ) return NULL;
 s = open_sock_tcp(port);
 if (! s) return NULL;

 res = telnet_negotiate(socket: s);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: strcat(login, '\r\n'));
 res = recv_until(socket: s, pattern: "[pP]assword:");
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: strcat(pass, '\r\n'));

 ps = '([$#%>] )|([a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+ +(/|(/[^/]+)+/*) *[$#%>])';

 res = recv_until(socket: s, pattern: ps);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: 'thisisnotaknowncommand'+rand()+'\r\n');
 res = recv_until(socket: s, pattern: ps);
#debug_print('Bad command => ', res);
 if ('thisisnotaknowncommand' >!< res)
 {
  close(s);
  return NULL;
 }
 return s;
}

##
# Runs command via rexec
#
# @param port rexec port
# @param login user to login with
# @param pass password to login with 
# @param cmd command to run
#
# @returns NULL if error, or string containing command result
##
function send_rexec(port, login, pass, cmd)
{
  local_var	s, buf;

  if ( ! get_port_state(port) ) return NULL;
  s = open_priv_sock_tcp(dport: port);
  if (! s) return NULL;
  send(socket: s, data: '\0');    # No separate channel for error :-(
  send(socket: s, data: strcat(login, '\0', pass, '\0', cmd, '\0'));
  buf = recv(socket: s, length: 1);  # 0 if OK?
  if ( isnull(buf) || ord(buf[0]) > 0)
  {
   close(s);
   return NULL;
  }
  buf = recv(socket: s, length: 1024*1024);
  close(s);
#debug_print('send_rexec: cmd = ', cmd, '\nbuf = \n', buf, '\n\n');
  return buf;
}

##
# Performs rlogin
#
# @param port rlogin port
# @param login username to login with
# @param pass password to login with
# @param from from user (optional, defaults to 'root')
#
# @return socket if successful, NULL if failure
##
function rlogin(port, login, pass, from)
{
 local_var	s, r;

 if ( ! get_port_state(port) ) return NULL;
 s = open_priv_sock_tcp(dport: port);
 if (!s) return NULL;
 if (! from) from = 'root';
 send(socket: s, data: '\0');
 send(socket: s, data: strcat(from, '\0', login, '\0raw/38400\0'));
 r = recv(socket: s, length: 1);
 if (r != '\0') { close(s); return NULL; }
 r = recv(socket: s, length: 1024*1024);
 if (r =~ 'Password *: *$')
 {
  send(socket: s, data: pass + '\r');
  r = recv(socket: s, length: 1024*1024);
  # display("'", ord(r[0]), "' (r)\n");
  if (r =~ 'Password *: *$')
  {
   close(s);
   return NULL;
  }
 }
 return s;
}

##
# Runs command via rsh
# 
# @param port rsh port
# @param login User to login as 
# @param from From user (optional, default is 'root')
# @param cmd Command to run
#
# @return NULL if error or string containing command output
##
function send_rsh(port, login, from, cmd)
{
 local_var	s, buf;

 if (! from) from = 'root';
 s = open_priv_sock_tcp(dport: port);
 if (! s) return NULL;
 send(socket: s, data: '0\0');	# No separate channel for error :-(
 send(socket: s, data: strcat(from, '\0', login, '\0', cmd, '\0'));
 buf = recv(socket: s, length: 1);  # 0 if OK?
 if (ord(buf[0]) > 0)
 {
  close(s);
  return NULL;
 }
 buf = recv(socket: s, length: 1024*1024);
 close(s);
 return buf;
}

##
# Run ssh/telnet/rsh/rexec/local command
#
# @param cmd Command to run
#
# @return NULL if error or result of command as string
##

function info_send_cmd(cmd)
{
 local_var	buf, f;

#debug_print('info_send_cmd: cmd=', cmd);

 if (info_t == INFO_LOCAL)
 {
  if (match(string: cmd, pattern: "cat *") && ">" >!< cmd)
  {
   f = substr(cmd, 4);
   if (! file_stat(f))
   {
#debug_print('info_send_cmd: ', f, ' does not exist or cannot be read\n');
    return NULL;
   }
   else
    return fread(f);
  }
  else
  {
   if ("'" >< cmd) sep = '"';
   else sep = "'";
   return pread(cmd: "/bin/sh", argv: make_list("sh", "-c", cmd));
  }
 }

 if (info_t == INFO_SSH)
 {
  return ssh_cmd(cmd: cmd, timeout: 120);
 }

 if (info_t == INFO_RSH)
 {
  return send_rsh(login: login, port: port_g, cmd:cmd);
 }
 if (info_t == INFO_REXEC)
 {
  return send_rexec(login: login, pass: pass, port: port_g, cmd:cmd);
 }

 if (info_t == INFO_TELNET)
 {
  send(socket: sock_g, data:
  # Yes! Two spaces (or more) are necessary
    strcat('echo NESSUS  START; ', cmd, ' 2>/dev/null; echo NESSUS  END\r\n'));
  # But just one space here!
  buf = recv_until(socket: sock_g, pattern: 'NESSUS END');
#debug_print('buf=>>>\n', buf, '<<<\n');
  recv_until(socket: sock_g, pattern: '[%$#>] ');
  # Only one space here!
  buf = strstr(buf, 'NESSUS START');
#debug_print('buf=>>>\n', buf, '<<<\n');
  c = buf - 'NESSUS START';
  while (c[0] == '\r' || c[0] == '\n' || c[0] == ' ' || c[0] == '\t')
   c = substr(c, 1);
  c = chomp(c - 'NESSUS END');
#if (c == buf) debug_print('info_send_cmd: could not extract command output from: ', buf);
#debug_print('c=>>>\n', c, '<<<\n');
  return c;
 }

 #log_print('info_send_cmd: unhandled case info_t=', info_t, ' - cmd=', cmd, '\n');
 return NULL;
}

##
# run a command from a template
# all variables are checked to prevent command injection
#
# @param template : arguments are presented as $<argument_number>$ in template
# @param args : list of arguments (optional)
# @return array s.t. 'data' contains the return value of the command
#               'error' contains the relevant error code.
function run_cmd_template(template, args, exit_on_fail)
{
  local_var i, arg, buf, err;
  i = 1;

  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (isnull(template))
  {
    err = 'run_cmd_template(): missing required arg "template"';
    if(exit_on_fail) exit(1, err);
    return make_array('error', HLF_NO_ARG);
  }

  # we shouldn't have variable in template if no arguments are present
  # coding error, so exit
  if (isnull(args) && ereg(pattern:"\$[0-9]+\$", string:template))
  {
    err = 'run_cmd_template(): Template variables present with no arguments.';
    if(exit_on_fail) exit(1, err);
    return make_array('error', HLF_MISMATCH);
  }

  # sanitize arguments to prevent command injection
  # attacks
  foreach arg (args)
  {
    # only allow whitelisted characters to prevent command injection
    # strings starting with '-' aren't allowed unless surrounded by quotes
    if (arg !~ '^(( *[*A-Za-z0-9_./\\[\\]][*A-Za-z0-9_.\\-/\\[\\]]*)*|'+
               '(\'[*A-Za-z0-9_.\\-/\\[\\] ]*\')|'+
               '("[*A-Za-z0-9_.\\-/\\[\\] ]*"))$')
    {
      err = 'run_cmd_template(): Invalid characters in argument "args"';
      if(exit_on_fail) exit(1, err);
      return make_array('error', HLF_INVALID);
    }
    template = ereg_replace(string:template, pattern:"\$" + i + "\$", replace:arg);
    i++;
  }
  # template variable number / argument number mismatch
  # coding error, so exit
  if (ereg(pattern:"\$[0-9]+\$", string:template))
  {
    err = "run_cmd_template(): The number of template variables mismatch the number of arguments provided.";
    if(exit_on_fail) exit(1, err);
    return make_array('error', HLF_MISMATCH);
  }

  buf = info_send_cmd(cmd:template);

  return make_array('data', buf, 'error', HLF_OK);
}

##
# Sets global variables
##
function set_globals()
{
 local_var opt;
 opt = get_kb_item("global_settings/report_verbosity");

 if (opt )
        {
        if ("Verbose" >< opt ) report_verbosity = 2;
        else if ("Normal" >< opt ) report_verbosity = 1;
        else if ("Quiet" >< opt ) report_verbosity = 0;
        }
}

set_globals();
