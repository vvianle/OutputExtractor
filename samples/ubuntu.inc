# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ubuntu.inc
#
# $Revision: 1.10 $
#


include("global_settings.inc");

##
# Storage value for release kb so we only need to fetch once.
##
global_var release;

##
# Storage value for package list kb so we only need to fetch once.
##
global_var dpkg_l;

##
# Internal storage value for reporting text on flag.
##
global_var _ubuntu_report;
_ubuntu_report = '';

##
# List storage of all remote packages found and checked
##
global_var _ubuntu_pkg_tests;
_ubuntu_pkg_tests = make_list();

##
# Adds package/reference info to the internal _ubuntu_report value 
#
# @param package Installed version of package
# @param reference Non-affected version of package
#
# @return No return if package and reference are non-empty and non-null
#         else NULL
##
function ubuntu_report_add(package, reference)
{
  if ( isnull(package) || !strlen(package) || isnull(reference) || !strlen(reference) )
  {
    return NULL;
  } 
  _ubuntu_report += '  - Installed package : ' + package + '\n' +
                    '    Fixed package     : ' + reference + '\n' +
                    '\n';
}

##
# Returns internal _ubuntu_report value 
#
# @return newline + _ubuntu_report if it has a strlen value 
#         NULL otherwise
##

function ubuntu_report_get()
{
  if (strlen(_ubuntu_report)) return '\n' + _ubuntu_report;
  else return NULL;
}

##
# Adds package to _ubuntu_pkg_tests list
#
# @anonparam First A full package/version combination from target system
##
function ubuntu_pkg_tests_add()
{
  local_var array, package;
  package = _FCT_ANON_ARGS[0];
  if (!package || !strlen(package)) return NULL;
  array = split(chomp(package), sep:'|', keep:FALSE);
  _ubuntu_pkg_tests = make_list(_ubuntu_pkg_tests, array);
}

##
# Sorts and uniques entries in _ubuntu_pkg_tests list, returns as string
#
# @return Sorted, unique list of rpms from _ubuntu_pkg_tests in a string
#           separated by " / "
##
function ubuntu_pkg_tests_get()
{
  local_var p, s, pkg_tests_unique, pkg_tests_array, package;

  if (max_index(_ubuntu_pkg_tests) == 0) return NULL;
  pkg_tests_array = make_array();
  pkg_tests_unique = make_list();
  foreach package (_ubuntu_pkg_tests)
    if (!pkg_tests_array[package]++) pkg_tests_unique = make_list(pkg_tests_unique, package);
  pkg_tests_unique = sort(pkg_tests_unique);

  s = "";
  foreach p (pkg_tests_unique)
    s += " / " + p;
	return substr(s, 3);
}

##
# Parses numerical and string portions of a version string into a list
#
# @param ver_str version string
#
# @return list of parts of string broken into digit parts and other parts 
##
function deb_parse_ver_str(ver_str)
{
  local_var ret_val, is_num, tmp, i;

  ret_val = make_list();

  tmp = ver_str[0];
  is_num = FALSE;
  if(tmp =~ "[0-9.]") is_num = TRUE;
  tmp = '';

  for(i=0; i<strlen(ver_str); i++)
  {
    if(ver_str[i] =~ "[0-9.]" && is_num == FALSE)
    {
      is_num = TRUE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    else if(ver_str[i] !~ "[0-9.]" && is_num == TRUE)
    {
      is_num = FALSE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    tmp = tmp + ver_str[i];
  }

  if(tmp != '') ret_val = make_list(ret_val, tmp);

  return ret_val;
}


##
# Compares two version string pieces
#
# @param s1 First version string piece
# @param s2 Second version string piece
#
# @remark This function only looks at the first max_len pieces of each
#           for whichever is shorter
#
# @return 1 if s1 > s2 in version parts from left to right
#         -1 if s1 < s2 in version parts from left to right
#         0 if s1 and s2 are equal through lowest max_len
##
function deb_str_cmp(s1, s2)
{
  local_var v1, v2, v1_len, v2_len,
            t1, t2, t1_len, t2_len,
            i,  j;

  v1 = deb_parse_ver_str(ver_str:s1);
  v2 = deb_parse_ver_str(ver_str:s2);

  v1_len = max_index(v1);
  v2_len = max_index(v2);

  for(i=0; i < v1_len && i < v2_len; i ++)
  {
    if(v1[i] =~ "^[0-9.]+")
    {
      t1 = split(v1[i], sep:'.', keep:FALSE);
      t2 = split(v2[i], sep:'.', keep:FALSE);
      t1_len = max_index(t1);
      t2_len = max_index(t2);

      for (j = 0; j < t1_len && j < t2_len; j++)
      {
        if (int(t1[j]) < int(t2[j]))
          return -1;
        if (int(t1[j]) > int(t2[j]))
          return 1;
      }
    }
    else
    {
      if(v1[i] < v2[i])
        return -1;
      if(v1[i] > v2[i])
        return 1;
    }
  }
  return 0;
}

##
# Compares two complete Ubuntu versions
#
# @param ver1 First version
# @param ver2 Second version
#
# @remark This function will remove RC entries from versions and then consider
#           which is greater if the version (not release) part is equal.
#
# @return 1 or more if ver1 > ver2 in version parts from left to right
#         -1 or less if ver1 < ver2 in version parts from left to right
#         0 if versions are equal
#         NULL if either version is an invalid format
##
function ubuntu_ver_cmp(ver1, ver2)
{
  local_var v1, v2, e1, e2, uv1, uv2, dr1, dr2, rc1, rc2, x;

  # Parse RCs
  rc1 = eregmatch(string: ver1, pattern: "^(.*)[.~\-+]rc([0-9]+)(.*)$", icase: 1);
  rc2 = eregmatch(string: ver2, pattern: "^(.*)[.~\-+]rc([0-9]+)(.*)$", icase: 1);
  if (! isnull(rc1))
  {
    ver1 = rc1[1] + rc1[3];
    rc1 = rc1[2];
  }
  if (! isnull(rc2))
  {
    ver2 = rc2[1] + rc2[3];
    rc2 = rc2[2];
  }

  v1 = eregmatch(string: ver1, pattern: "^([0-9]+:)?([^-]+)(-([a-z0-9+.-]+))?$", icase: 1);
  v2 = eregmatch(string: ver2, pattern: "^([0-9]+:)?([^-]+)(-([a-z0-9+.-]+))?$", icase: 1);

  if (isnull(v1) || isnull(v2)) return NULL;
  e1 = int(v1[1]); uv1 = v1[2]; dr1 = v1[4];
  e2 = int(v2[1]); uv2 = v2[2]; dr2 = v2[4];

  if (e1 != e2) return e1 - e2;
  x = deb_str_cmp(s1: uv1, s2: uv2);
  if (x) return x;
  if (! isnull(rc1) && isnull(rc2))
  {
    return -1;
  }
  if (isnull(rc1) && ! isnull(rc2))
  {
    return 1;
  }
  if (! isnull(rc1) && ! isnull(rc2) && rc1 != rc2)
  {
    return int(rc1) - int(rc2);
  }
  x = deb_str_cmp(s1: dr1, s2: dr2);
  return x;
}

##
# Checks if package below a reference version is installed.
#
# @param pkgname package name (ie: python)
# @param osver OS version 
# @param pkgver version and release number (ie: 2.6.6-3+squeeze7)
#
# @remark This function has the side-effect of modifying ubuntu_report
#
# @return 0 if uptrack is installed but disable file unavailable
#              and package begins with kernel
#         verion string installed if package installed and
#              package < pkgver and Host OS release == osver 
#         NULL otherwise
##
function ubuntu_check(osver, pkgname, pkgver)
{
 local_var installed, ver, v;

 if (get_kb_item("Host/uptrack-uname-r") && !get_kb_item("Host/uptrack-disable-file") && match(pattern:"kernel*", string:pkgname)) return 0;

 if (! release) release = chomp(get_kb_item("Host/Ubuntu/release"));
 if (release != osver) return NULL;

 if (!dpkg_l) dpkg_l = get_kb_item("Host/Debian/dpkg-l");
 installed = egrep(string: dpkg_l, pattern: '^ii +' + pkgname + '(:\\w+)? +');
 if (! installed) return NULL;

 ver = ereg_replace(	string: installed, replace: "\2",
			pattern: '^ii +' + pkgname + '(:\\w+)? +([^ ]+) +.*$');
 if (ver == installed) return NULL;	# cannot extract version
 ubuntu_pkg_tests_add( pkgname + '_' + ver );
 if (ubuntu_ver_cmp(ver1: ver, ver2: pkgver) < 0)
 {
   ubuntu_report_add(package:pkgname+"_"+ver, reference:pkgname+"_"+pkgver);
   return ver;
 }
 return NULL;
}
