#TRUSTED 6223fd0cc2ca3e914aa6d9f02be830759a23d8128826498ae2f3d43a63a50ae65e0b98e95ad3aba428f813fdf7baac9240f9fd60d03843a58993d8a034f2f798f4905e77502bb8052a917f54feb357b40907bcf3d4008b48818a3158cff32533baa76adaa08715416c939c46ce9448b34d590ea706178e58c004d13ba2545a4981bd74c2426de8e9e6ee98dd0cd615d5787f06ce5476bd4848b7bda23627bfe5f5459c5b868a1ece29d20384ea4b6ffa555fae26b373519cc9ec30d12941ddfb7d17fb0000b7387f27d30d681424185fb0ccba163f8f8fa64e2a68f3fba95f7f75b5da5c2f49807ad2abb4d8605da80f2af264950c71d0e3e88d04386b9902b58fa2da1717b3cb46528cc32ced1235282439abd8eb5ca05ea6b1ee2eb16c285081c389807bff190303f60b2fa5b5f1a4b9dc0b280b0c3a479d7be599d3eb2b8fb50d7d265c3ab34eb7718e4a1d714def8f7fc03d5d487051739fefd85977172c39fa3c2d48aed937e20a513e469440789c17f02e2460a02b09b018a748e417e35288f5c45f2244fef23214f1f33bdb75aef472a2f2e7ac95ee4d634c8ae95a110f6f330eb4535e3f01eebef74956d8d985fffe0e60f1066fd2a0e6b25c5d11528e4049da74925569b1d3be84cc5f90d2e751ad29088e75568805139f04d3cca7e3894ec81f2f53cbdf07a2b9f5db9563c515071259ccb20d45fed185e0052e67
#
# (C) Tenable Network Security, Inc.
#
# v1.36

global_var	experimental_scripts, report_verbosity, debug_level, thorough_tests, report_paranoia, supplied_logins_only;

experimental_scripts = 0;
report_verbosity = 1;
debug_level = 0;
thorough_tests = 0;
report_paranoia = 1;
all_addr_private = 0;
all_addr_public = 0;
supplied_logins_only = 0;

SECURITY_HOLE    = 'Hole';
SECURITY_WARNING = 'Warning';
SECURITY_NOTE    = 'Note';

if (  get_kb_item("global_settings/supplied_logins_only") ) 
{
 supplied_logins_only = 1;
}

__gs_opt = get_kb_item("global_settings/network_type");
if (__gs_opt)
{
  if ("LAN" >< __gs_opt) all_addr_private = 1;
  else if ("Internet" >< __gs_opt) all_addr_public = 1;
}

__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}

__gs_opt = get_kb_item("global_settings/report_paranoia");
if (__gs_opt)
{
  if ("Avoid false alarms" >< __gs_opt) report_paranoia = 0;
  else if ("Normal" >< __gs_opt) report_paranoia = 1;
  else if ("Paranoid" >< __gs_opt) report_paranoia = 2;
}

__gs_opt = get_kb_item("global_settings/debug_level");
debug_level = int(__gs_opt);
if (debug_level < 0) debug_level = 0;

__gs_opt = get_kb_item("global_settings/experimental_scripts");
if ( __gs_opt )
{
   if ( "no" >< __gs_opt ) experimental_scripts = 0;
   else if ("yes" >< __gs_opt) experimental_scripts = 1;
}

__gs_opt = get_kb_item("global_settings/thorough_tests");
if ( __gs_opt )
{
 if ( "no" >< __gs_opt) thorough_tests = 0;
 else if ("yes" >< __gs_opt) thorough_tests = 1;
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function debug_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level < level) return;
 if ( NASL_LEVEL < 2191 ) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("DEBUG: ", msg);
}

# Only use this function to print a fatal error, e.g. a violation of an API
function err_print(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if ( NASL_LEVEL < 2191 ) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("ERR: ", msg);
}

##
# Taken from http_misc_func.inc
#
# @param resp       Text from our response to include in the report
# @param max_lines  Max number of lines to include of output. Default to 10
##
function beginning_of_response2(resp, max_lines)
{
  local_var     txt, i, line;

  if (isnull(resp))
    return err_print('beginning_of_response2: missing parameter resp.');

  if (max_lines <= 0) max_lines = 10;
  i = 0;
  foreach line(split(resp, keep: 0))
  {
    line = chomp(line);
    line = ereg_replace(string: line, pattern: '^[ \t]+', replace: '');
    txt += line + '\n';
    if (++ i  >= max_lines) return txt + '[...]\n';
  }
  return txt;
}

##
# security_report will appear in Nessus 5
#
# @param port       port number of the web server
# @param severity   report severity (note, warning, hole)
# @param extra      report text to display
# @param cmd        Command executed.  Used in the report output.  If TRUE
#                   use code/command execution report
# @param file       File to use in report. If TRUE, use reporting for lfi/rfi
# @param request    array list of request(s) used in report output
# @param output     Output to use in report for file_read or cmd_exec
#                   Is an optional param when generic is TRUE
# @param line_limit Number of output lines to display in report. 10 by default
# @param rep_extra  Any extra text to include in the report output (optional)
# @param attach_type Attachment type used with security_report_with_attachments
#                    defaults to 'text/plain' in none provided.
# @param generic    Used for reporting of general SQLi / XSS vulns
#                   When generic is TRUE, output can be optional
# @param sqli       If TRUE, sets SQLInjection KB item
# @param xss        If TRUE, sets XSS KB item
# @param xsrf       If TRUE, sets XSRF KB item
##
function security_report_v4(port, severity, extra, cmd, file, request, output, line_limit, rep_extra, attach_type, generic, sqli, xss, xsrf)
{
  local_var attach_level, snip, s, report, rep_footer, rep_header;
  local_var num_req, attachments, i;

  if (isnull(severity))
    return err_print('security_report_v4: missing parameter severity.');
  if (isnull(port))
    return err_print('security_report_v4: missing parameter port.');

  if ( (!isnull(cmd)) || (!isnull(file)) )
  {
    if (isnull(request))
      return err_print('security_report_v4: missing parameter request.');
    if (isnull(output))
      return err_print('security_report_v4: missing parameter output.');
  }

  # These are set unconditionally
  if (xss)
    replace_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (xsrf)
    replace_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (sqli)
    replace_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  attach_level = 2;  # Default value
  if (severity == SECURITY_NOTE) attach_level = 0;
  if (severity == SECURITY_WARNING) attach_level = 2;
  if (severity == SECURITY_HOLE) attach_level = 3;

  if (isnull(line_limit))
    line_limit = 10;

  if (isnull(attach_type))
    attach_type = 'text/plain';

  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  rep_footer = crap(data:"-", length:66);

  if (!isnull(cmd))
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nNessus was able to execute the command "' + cmd + '" using the' +
      '\nfollowing request' + s + ' :' +
      '\n' + 
      '\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    report +=
      '\n\n' + 'This produced the following truncated output (limited to ' +
      line_limit + ' lines) :' +
      '\n' + snip +
      '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
      '\n' + snip +
      '\n';

    if (severity == SECURITY_HOLE)
      security_hole(port:port, extra:report);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, extra:report);
    else
      security_note(port:port, extra:report);
  }

  else if (!isnull(file))
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nNessus was able to exploit the issue to retrieve the contents of ' +
      '\n' + "'" + file + "'" + ' using the following request' + s + ' :' +
      '\n' +
      '\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report +=
        '\n' + 'This produced the following truncated output (limited to ' +
        line_limit + ' lines) :' +
        '\n' + snip +
        '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
        '\n' + snip +
        '\n';

      if (severity == SECURITY_HOLE)
        security_hole(port:port, extra:report);
      else if (severity == SECURITY_WARNING)
        security_warning(port:port, extra:report);
      else
        security_note(port:port, extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< file) file = ereg_replace(
        pattern:"^.+/([^/]+)$", replace:"\1", string:file);
      if ("\" >< file) file = ereg_replace(
        pattern:"^.+\\([^\\]+)$", replace:"\1", string:file);

      report +=
        '\n' + 'Attached is a copy of the response' + '\n';
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = attach_type;
      attachments[0]["name"] = file;
      attachments[0]["value"] = output;
      security_report_with_attachments(
        port  : port,
        level : attach_level,
        extra : report,
        attachments : attachments
      );
    }
  }

  else if (generic)
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nNessus was able to exploit the issue using the following request'
      + s + ' :\n\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    # Allow output to be optional for Generic cases.
    if (!isnull(output))
    {
      report +=
        '\n\n' + 'This produced the following truncated output (limited to ' +
        line_limit + ' lines) :' +
        '\n' + snip +
        '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
        '\n' + snip +
        '\n';
    }

    if (severity == SECURITY_HOLE)
      security_hole(port:port, extra:report);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, extra:report);
    else
      security_note(port:port, extra:report);
  }

  else if (report_verbosity < 1 || isnull(extra))
  {
    if (severity == SECURITY_HOLE)
      security_hole(port);
    else if (severity == SECURITY_WARNING)
      security_warning(port);
    else
      security_note(port);
  }
  else
  {
    if (severity == SECURITY_HOLE)
      security_hole(port:port, extra:extra);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, extra:extra);
    else
      security_note(port:port, extra:extra);
  }
}

GLOBAL_SETTINGS_INC = 1;
