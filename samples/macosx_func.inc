#TRUSTED a02c0ae2ece2613fb156cd9e46c9a5517319a42cf5a4ab0e2170c456ec65796fb89eb8eb154bc7fb5328688d3e3cbe59a79272ec3333692c5485e70d58d420bada7d55db6f552c614cbbe6cc46777f1b2c208dfa4ed5a93deda7ef210e3d8905e4a12baa583b2eac05f6cf3d4c98dba0ed942f5d497f1acf307f2499bb1e042442e9a5a839adb43cb1ba7ab133c4ed15b819708c578926ceb6719df2106a3b7ac8a7865acf493dcc066e33918230acc08016191295699671de6929e6be1006ad5aeb148295f4927e66e098d079a06d0c187123a7ed3cbeaff3df5c61d5127cbd6851f62ed0531bcea0178ac824f6e9e28932a4b92f17491bf49bbf3f2ee001e3afd2dae0300230c1643822144b2252ad83e0b0450a93c92aeb063cdf786b23d3ac66b97b87a727063d626c9340da09eb06066dd8866d8215f67d84c0add134208f6f17f3aa47b5f574be786a82d2f38c4917fe054c69601a9c1558cfe8727a3b783fb3cfd28e8e1c15bcae65b563a819918d07015fccdaf7a28e6b16d30b96b7988e03b8e9b07fedc379e65ee368758fdb4f3b2c387b72b0a4c9e8dcd9944f415d17361ad5667b97718b4bd45137c88952ecf97c0d401de890ff53737c0f46f10c775df257451029c6295cd402c6ef031053b68430524e3de20cdd84f6d14dad874f50866981892c3e7bf8a6e4dfa6d1249df91d8caf53272d063af26039673b
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# v1.7

##
# Generates OSX Bundle Version
#
# @param file filename of bundle
# @param path path to bundle
# @param label plist tag for the version info
# @param rsrc True for rsrc, otherwise false
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function _GetBundleVersionCmd(file, path, label, rsrc)
{
  local_var ret, suffix;
  local_var cmd;

  # This is only invoked by GetCarbonVersionCmd
  if ( rsrc )
  {
    suffix = "/rsrc";
    cmd = "perl -pe 's/[^ -~]/\\n/g'";
  }
  else
  {
    suffix = "/Contents/version.plist";
    cmd    = "cat";
 }

 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && ";
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
 return ret;
}

##
# Generates OSX Bundle Version
#
# @param file filename of bundle
# @param path path to bundle
# @param long If true uses CFBundleVersion otherwise CFBundleShortVersion
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function GetBundleVersionCmd(file, path, long)
{
 if ( long )
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:FALSE);
 else
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleShortVersion", rsrc:FALSE);
}

##
# Generates OSX Bundle Version
#
# @param file
# @param path
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function GetCarbonVersionCmd(file, path)
{
 return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:TRUE);
}

##
# Executes a command on localhost or via ssh.
#
# @param cmd Command to be executed on the target host.
# @param exit_on_fail True/False if the script should exit on fail, returns NULL if False and fails.
#
# @category OSX
#
# @return The result of the executed command or NULL on failure.
##
function exec_cmd(cmd, exit_on_fail)
{
  local_var ret, buf;

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  if (islocalhost())
    buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();

    if (!ret)
    {
      if (exit_on_fail) exit(1, "ssh_open_connection() failed.");
      else return NULL;
    }

    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (buf) buf = chomp(buf);
  return buf;
}

##
# Executes a array of unique commands on localhost or via ssh.
#
# @param cmds Array of unique commands to be executed on the target host.
# @param exit_on_fail True/False if the script should exit on fail, returns NULL if False and fails.
#
# @category OSX
#
# @return An hash of the results of the executed commands or NULL on failure.
##
function exec_cmds(cmds, exit_on_fail)
{
  local_var command, ret, buf, results;

  if (typeof(cmds) != 'array')
    exit(1, "Invalid type for the 'cmds' argument.");

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  results = make_array();
  cmds = list_uniq(cmds);

  if (!islocalhost())
  {
    ret = ssh_open_connection();

    if (!ret)
    {
      if (exit_on_fail)
        exit(1, "ssh_open_connection() failed.");
      else
        return NULL;
    }
  }

  foreach command (cmds)
  {
    buf = "";

    if (islocalhost())
      buf = pread(cmd:"bash", argv:make_list("bash", "-c", command));
    else
    {
      buf = ssh_cmd(cmd:command);

      if(isnull(buf))
      {
        if(exit_on_fail == TRUE)
          exit(1, "ssh_cmd() failed.");
      }
    }

    if (buf)
      buf = chomp(buf);

    results[command] = buf;
  }

  if (!islocalhost()) ssh_close_connection();

  return results;
}


##
# Gets the list of user directories
#
# @param all True/False if the script should extract all user directories or just those of regular users (ie, with an id > 499)
#
# @category OSX
#
# @return An array in which the keys are the usernames and the values are the home directories.
##
function get_users_homes(all)
{
  local_var cmd, data, home, homes, id, key, line, match, res, val;

  cmd = 'echo ; /usr/bin/dscl  . -readall /Users NFSHomeDirectory UniqueID';
  res = exec_cmd(cmd:cmd);
  if (!strlen(res)) return NULL;

  homes = make_array();
  foreach line (split(res, keep:FALSE))
  {
    match = eregmatch(pattern:"^([^: ]+): +(.+)$", string:line);
    if (match)
    {
      key = match[1];
      val = match[2];
      data[tolower(key)] = val;
    }

    if (!isnull(data['uniqueid']) && !isnull(data['recordname']) && !isnull(data['nfshomedirectory']))
    {
      id = data['uniqueid'];
      if (all || id > 499)
      {
        key = data['recordname'];
        val = data['nfshomedirectory'];
        homes[key] = val;
      }

      data = make_array();
    }
  }
  return homes;
}
