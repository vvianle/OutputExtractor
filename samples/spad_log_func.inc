#TRUSTED 8230d03d5aeb43b1abe5d4df34af324c02f776d56a393d2bc535a0416389faa83c11d1c8b0e63213fe031cb0801a033e0dfad1d609145ca9ebc11bc7e7122c94764ce3b036124f730f7ae907347e462ffa8518463fb5d1e7e90e2864e6d796b7b77657df9889a3cbe1725c3744ad905c31a2d7579695f0e1dd91b5b72e36db249370177ce83bb72ec4b1721235278a5c8421bdb9c418ff40e1dca1cfcd65fcd4831338a0ac778ceded27309e001cf7550bf7d2dd3c0f6c85fb82e7ebc23bcf7df87af46f3146dca2325b682fcbc9f4134206c22026a157995ef3da0807032efcff1d0b08d2a83ecf9339dd767d69abeb9a074e657b7e7cc47095c9eb54f7c4e8e707cd9bf5eaf88d6c6a0fa2874629c5250479a860f6a0535fd709f6d29683a2257975f7c0b63e73e7fb839eddc8ba3f5837ae733076a8ec2a35e93748570354dd028a90249256d89356ee232d75579e494963c28cd197875c2e91a5faa96b98c49002cd2423491633d6059b3c22cd4be759df349664bef305812b9ef0dbc85cc4255c57798786b8464a0a85dabc48751a1446e78d1ea22db220315b333eaf8cdf4b332fa1f0a27f66fa43cd50d42830155fd753275e09fa1ee95b02e4ba9235b4dae28ca0c5006e5beb132f43e0ef810c69ff901afb38e0ed1ae2049a40727468f2c3c10882b1fc8063684b46f0805fa6a59254f0f20b6ba477af0006e6dbbe

###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# @include misc_func.inc
#
###

##
# Name of the table where logs are stored.
##
global_var __SPAD_LOG_TABLE_NAME;
__SPAD_LOG_TABLE_NAME  = "logstore";

##
# For thread safety (some plugins call branch/fork)
##
global_var __SPAD_LOG_SQLDB_MUTEX;
__SPAD_LOG_SQLDB_MUTEX = __SPAD_LOG_TABLE_NAME + "_" + get_host_ip();

##
# Table definition for spad log table
#
# id      : log message id (integer auto increments)
# name    : log file name (128 CHAR) used when attached as a file, should be unique
#           for a logging session e.g. "ssh_get_info.log" or "virus_scanner_debug.log"
#           defaults to SCRIPT_NAME.log. This column is indexed.
# time    : time stamp for message, will be pre-appended to message when log created
# message : log message (unrestricted TEXT)
##
global_var __SPAD_LOG_TBL_SQL;

##
# SQL to insert a new log message
##
global_var __SPAD_LOG_INS_SQL;

##
# SQL to get unique log names
##
global_var __SPAD_LOG_NAM_SQL;

##
# SQL to check if table is created
##
global_var __SPAD_LOG_CHK_SQL;

##
# SQL to get text / time data for single log
##
global_var __SPAD_LOG_TXT_SQL;

__SPAD_LOG_INS_SQL = "INSERT INTO "+__SPAD_LOG_TABLE_NAME+" (name,message) VALUES(?,?)";
__SPAD_LOG_NAM_SQL = "SELECT DISTINCT name FROM "+__SPAD_LOG_TABLE_NAME;
__SPAD_LOG_CHK_SQL = "SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table' AND name='" +__SPAD_LOG_TABLE_NAME+"'";
__SPAD_LOG_TXT_SQL = "SELECT time,message FROM "+__SPAD_LOG_TABLE_NAME+" WHERE name=? ORDER BY time";
__SPAD_LOG_TBL_SQL =
  "CREATE TABLE IF NOT EXISTS "+__SPAD_LOG_TABLE_NAME+" (" +
    "id      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
    "name    CHAR(128) NOT NULL ," +
    "time    DATETIME DEFAULT current_timestamp, " +
    "message TEXT" +
  "); " +
  "CREATE INDEX IF NOT EXISTS logstore_name_idx ON "+__SPAD_LOG_TABLE_NAME+"(name)";

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'.
#
# @param message string required - message to log
# @param name    string optional - name of the log handle to log message
#                                  defaults to <SCRIPT_NAME>.log
#
# @remark Returns immediately if kb item 'global_settings/enable_plugin_debugging'
#         is not set.
#
# @remark If you are running in "CLI Mode" messages will be displayed directly
#         to the STDOUT and name will be ignored entirely.
#
# @remark It's highly recommended if you're logging in a plugin that branches / 
#         forks to not use the default name or to pre-append a thread specific
#         identifier to message, e.g.:
#
#            port = branch(list_of_ports)
#            spad_log(message:"("+port+") Opening connection ...");
#
#         Remember that functions like get_kb_item and get_single_install can
#         branch depending on the structure of the KB, its up to you to decide
#         if thread specific logging is appropriate for your logging needs in
#         these situations.
##
function spad_log(message,name)
{
  # Skip if plugin logging not enabled
  if(!get_kb_item("global_settings/enable_plugin_debugging"))
    return;

  # Set default values
  if(isnull(name))
    name = ((SCRIPT_NAME - ".nasl") - ".nbin") + ".log";
  # Catch dev mistakes
  if(typeof(name) !~ '(data|string)')
    return err_print("Parameter 'name' is null or an invalid type.");
  if(isnull(message) || typeof(message) !~ '(data|string)')
    return err_print("Parameter 'message' is null or an invalid type.");

  # If we're not running in CLI mode log to spad db
  if(!isnull(get_preference("plugins_folder")))
  {
    _spad_log_to_db(message:message,name:name);
  }
  # If we are in CLI mode show message directly
  else
  {
    display(message);
    if(message !~ '\n$')
      display('\n');
  }
}

##
# Returns a structure that can be attached with security_report_with_attachments
##
function spad_log_get_report_attachments()
{
  local_var names,row,msgs,logs,txt,lidx;

  if(!_spad_log_has_inited())
    return NULL;

  names = query_scratchpad(__SPAD_LOG_NAM_SQL);

  if(empty_or_null(names))
    return NULL;

  logs = make_list();
  lidx = 0;
  foreach row (names)
  {
    if(isnull(row['name']))
      continue;

    txt = _spad_log_get_txt(name:row['name']);

    if(isnull(txt))
      continue;

    logs[lidx] = make_array();
    logs[lidx]["type" ] = "text";
    logs[lidx]["name" ] = row['name'];
    logs[lidx]["value"] = txt;
    lidx += 1;
  }
  return logs;
}

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'. Does
# the scratch pad database interaction only.
#
# @param message string required - message that to log
# @param name    string required - name of the log handle to log message
#
##
function _spad_log_to_db(message,name)
{
  if(typeof(name) !~ '(data|string)')
    return err_print("Parameter 'name' is null or an invalid type.");
  if(isnull(message) || typeof(message) !~ '(data|string)')
    return err_print("Parameter 'message' is null or an invalid type.");

  if(!_spad_log_has_inited())
    _spad_log_init();

  query_scratchpad(__SPAD_LOG_INS_SQL,name,message);
}

##
# Get the log text for particular log
#
# @param name string required - name of the log to get the text of
#
# @remark a new line if always added to the end of messages if one
#         is not already present
##
function _spad_log_get_txt(name)
{
  local_var ret,row,txt;

  if(isnull(name) || typeof(name) !~ '(data|string)')
    return err_print("Parameter 'name' is null or an invalid type.");
  
  ret = query_scratchpad(__SPAD_LOG_TXT_SQL, name);

  if(empty_or_null(ret))
    return NULL;
  txt = NULL;
  foreach row (ret)
  {
    txt += "["+row['time']+"] "+row["message"];
    if(txt !~ '\n$') txt += '\n';
  }
  return txt;
}

##
# Creates the necessary SQLite tables for logging
##
function _spad_log_init()
{
  query_scratchpad(__SPAD_LOG_TBL_SQL);
}

##
# Checks to see the log structures have been initialized
##
function _spad_log_has_inited()
{
  local_var ret;

  ret = query_scratchpad(__SPAD_LOG_CHK_SQL);

  if(isnull(ret) || ret[0]["cnt"] == 0)
    return FALSE;
  return TRUE;
}
