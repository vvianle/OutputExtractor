#TRUSTED 52342635d3dc40687536907d44ed7e0655f47d8481471e8876f389cbb108efa4b8b348d5ba59407e920b9a4100e8c8ee58f0debc91b0e5d1ab2bd9c6d96f61603e47af3f393f38b6d8ed1afcbdc19e08f904187095fb17255ec5e8e942fb4f29f5015f2dfaa8f9138043bd990b30435c040af3d95461b7208087d3adbf0215de93ac0e4415bd935a5a74cbc020a2bc17f28dbffd4774b3cd41d47af3ddcc65b835cdeb57e8da3fa66a741c6fb260e66961da706dcd621ff330090188376b47e6052158a09a7cc9970ec4ab063f49dc2982b33e987d74de971286f92b075eedaaff8825d61182959e43561252f8cedfc5df972330c09be3f37347bc0f546d838f2ce24224ebcf429edbe558b29e219d609ae4b6039393489569abdfc0acdc99205313b2b71650b7766856c27dc064f6b84a59da4bb50283d59f3acc8b8d1dc736e6e944712714583068f639e4bf56d6c7228c1bd278ccf2672cf0acf57bf94ffbe1ab151ded6c1b0143cfc35191869f196156092f56558753486cc957012693e1f1d1370114d3096667ac826d562bc3622f1a987049ef75d4bec4d8a6e928d972fe6d2789932fea0337bf284ebd1899a795a64b2653d09b91274346132fe92a519e5047c95a36467c50adbb0c08bb416fd2980a45096c9ed6b58baf7431b9957fa786eea97af18530f7b45a9945bab0a808d0fa3a066f76c1ce8084007f427a39
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# cisco_func.inc
# Revision: 1.18
###


if ( NASL_LEVEL < 2191 ) exit(0);

include("global_settings.inc");
include("misc_func.inc");

global_var no_build;
global_var patch_update;

##
# Determines if additional comments need to be added to the report string
#
# @anonparm override override is a flag which can be used to force the caveat to be displayed
#
# @return NULL or caveat string stating that creds were not provided.
##
function cisco_caveat()
{
  local_var CredsProvided;
  local_var override;

  CredsProvided = 0;
  if (get_kb_item("Host/local_checks_enabled"))  CredsProvided = 1;

  override = _FCT_ANON_ARGS[0];
  if (override) CredsProvided = 0;

  if ( CredsProvided ) return NULL;
  else return '\nNote that valid host or enable credentials were not provided for the\nremote device and therefore it was not possible to determine whether\nthis vulnerability applies to your configuration.' ;
}

##
# Extracts IOS version number from an SNMP sysDesc
#
# @anonparm sysDesc sysDesc string to extract IOS version from
#
# @return IOS version extracted from 'sysDesc', or
#         NULL if an IOS version could not be extracted from it
##
function extract_version()
{
 local_var ret;
 ret = ereg_replace(pattern:".*.*Version ([0-9.]*\([0-9a-z]*\)[A-Z]*[0-9]*[a-z]*(\([0-9a-z]*\))*),.*",
	            replace:"\1",
		    string:_FCT_ANON_ARGS[0]);

 # check if the regex failed
 if (ret == _FCT_ANON_ARGS[0])
   ret = NULL;

 return ret;
}

##
# Extracts ASA version from the given line
#
# e.g. pass in "Cisco Adaptive Security Appliance Software Version 8.2(2)4"
#
# get back "8.2(2)4"
#
# @anonparam  line  line of text to parse ASA version from
#
# @return ASA version number if it could be extracted from 'line',
#         NULL otherwise
##
function extract_asa_version()
{
 local_var line, match, ver;
 line = _FCT_ANON_ARGS[0];
 if (isnull(line)) return NULL;

 line = chomp(line);
 match = eregmatch(pattern:".*Version ([0-9.\(\)]+)$", string:line);
 if (isnull(match)) ver = NULL;
 else ver = match[1];

 return ver;
}

##
# Extracts NX-OS version from the given line
#
# @anonparam  line  line of text to parse version from
#
# @return NX-OS version number if it could be extracted from 'line',
#         NULL otherwise
##
function extract_nxos_version()
{
 local_var line, match, ver;
 line = _FCT_ANON_ARGS[0];
 if (isnull(line)) return NULL;

 line = chomp(egrep(pattern:"system:\s+version\s", string:line));
 match = eregmatch(pattern:".*system:\s+version\s+([0-9a-zA-Z\..\(\)]+).*$", string:line);
 if (isnull(match)) ver = NULL;
 else ver = match[1];

 return ver;
}

##
# compares two alphanumeric strings. this is more or less a character
# by character comparison based on ascii value
#
# @anonparam a string to compare
# @anonparam b string to compare
#
# @return 0 if a == b,
#         negative integer if a < b,
#         positive integer if a > b
##
function cmpv()
{
 local_var a,b,i,min;
 local_var ia, ib;
 local_var j, la, lb;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];

 # Ignore leading part that is the same in both version strings.
 la = strlen(a);
 lb = strlen(b);
 for (j=0; j<la && j<lb; j++)
 {
  if (a[j] != b[j]) break;
 }
 if (j > 0)
 {
  if (j == la || j == lb) j--;
  a = substr(a, j);
  b = substr(b, j);
 }

 # if both strings are all numeric, all that's left to do is the comparison
 if ( ereg(pattern:"^[0-9]*$", string:a) && ereg(pattern:"^[0-9]*$", string:b) )
	{
	return int(a) - int(b);
	}

 # otherwise, extract numbers from the beginning of each string
 # no attempt is made to verify these regexes succeed (safe assumption?)
 ia = int(ereg_replace(pattern:"^([0-9]*).*$", string:a, replace:"\1"));
 ib = int(ereg_replace(pattern:"^([0-9]*).*$", string:b, replace:"\1"));
 a  -= ia;
 b  -= ib;
 # return if the numeric portions differ
 if ( ia != ib ) return ia - ib;
 

 # compare the remainder of each string (the original string minus the
 # leading numeric parts) character by character. compare up to 'min'
 # characters where 'min' is the length of the shorter of the two strings.
 min = strlen(a);
 if ( strlen(b) < min )
	min = strlen(b);

 for ( i = 0 ; i < min ; i ++ )
 {
  if ( ord(a[i]) != ord(b[i]) )
	return ord(a[i]) - ord(b[i]);
 }

 # if there were still no differences seen, the last comparison is to see
 # if one string is longer than the other
 if ( strlen(a) > min ) 
	return 1;
 else if ( strlen(b) > min )
	return -1;
 else 
	return 0;
}

##
# Takes two IOS versions and compares their train (and everything that follows)
# E.g. if '11.1(4)T6' and '11.1(4)T7' are provided, 'T6' is compared to 'T7'
#      if '12.0(6.5)W5(16.0.9)' and '12.0(6.5)W4' are provided, 'W5(16.0.9)' is compared to 'W4'
#
# @anonparam a IOS version to compare
# @anonparam b IOS version to compare
#
# @return NULL if either version does not have a train/build
#         negative number if a's train/build < b's train/build
#         0 if a's train/build == b's train/build
#         positive number if a's train/build > b's train/build
#
#         the 'no_build' global is set to 1 when NULL is returned,
#         and set to 0 when a non-NULL value is returned
##
function cmp_build()
{
 local_var a, b, s1, s2;
 local_var array1, array2;
 local_var n, i;


 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 no_build = 0;

 s1 = eregmatch(pattern:"[0-9.]*\([0-9a-z.]*\)([A-Za-z0-9\(\)\.]*)", string:a);
 if ( isnull(s1) )
	{
	  no_build = 1;
	  return NULL;
	}
 s2 = eregmatch(pattern:"[0-9.]*\([0-9a-z.]*\)([A-Za-z0-9\(\)\.]*)", string:b);
 if ( isnull(s2) )
	{
	  no_build = 1;
	  return NULL;
	}
 
 return cmpv(s1[1], s2[1]);
}



##
# Compares the release number of two IOS versions.
# For IOS version 'w.x(y)z', 'y' is the release number
#
# @anonparam a IOS version to compare
# @anonparam b IOS version to compare
#
# @return negative number if a's release < b's release
#         0 if a's release == b's release
#         positive number if a's release > b's release
##
function cmp_release()
{
 local_var a, b, s1, s2;
 local_var array1, array2;
 local_var n, i;


 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 # no attempt is made to check if these regexes succeed (safe assumption?)
 s1 = eregmatch(pattern:"[0-9.]*\(([0-9a-z.]*)\)[A-Z]*[0-9]*", string:a);
 s2 = eregmatch(pattern:"[0-9.]*\(([0-9a-z.]*)\)[A-Z]*[0-9]*", string:b);
 
 return cmpv(s1[1], s2[1]);
}


##
# Compares the major version, minor version, and (optionally) release train identifier of two IOS versions
# E.g.,
#   if '11.0(3)' and '11.2(14)BT' are provided, '11.0' is compared to '11.2BT' (return -1)
#   if '12.0(3)AA' and '12.0(14)BT' are provided, '12.0AA' is compared to '12.0AA' (return 0)
#
# @anonparam a version to compare
# @anonparam b version to compare
#
# @return -1 if the release train IDs differ
#          negative number if a's major/minor < b's major/minor
#          0 if a and b have the same major/minor/release train IDs
#          positive number if a's major/minor > b's major/minor
##
function cmp_version()
{
 local_var a, b, s1, s2, b1, b2;
 local_var array1, array2;
 local_var n, i;


 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 # Extract the major/minor version numbers and the release train ID
 s1 = eregmatch(pattern:"([0-9.]*)\([0-9a-z.]*\)([A-Z]*)[0-9]*[a-z]*", string:a);
 s2 = eregmatch(pattern:"([0-9.]*)\([0-9a-z.]*\)([A-Z]*)[0-9]*[a-z]*", string:b);
 if (isnull(s1) || isnull(s2))
   return -1;

 # For 12.2S releases, a 3rd uppercase letter may follow the train identifier.
 # This is not part of the train identifier - it's a new technology identifier
 if (s1[1] == "12.2" && s1[2] =~ '^S' && strlen(s1[2]) == 3)
   s1[2] = substr(s1[2], 0, 1);
 if (s2[1] == "12.2" && s2[2] =~ '^S' && strlen(s2[2]) == 3)
   s2[2] = substr(s2[2], 0, 1);

 # bail out if the versions have different train identifiers
 if ( s1[2] != s2[2] )
	return -1;
 
 # if the trains are the same, compare the major and minor version numbers
 array1 = split(s1[1], sep:'.', keep:FALSE);
 array2 = split(s2[1], sep:'.', keep:FALSE);
 n = max_index(array1);

 for ( i = 0 ; i < n ; i ++ )
 {
  if ( array1[i] != array2[i] )
	return cmpv(array1[i], array2[i]);
 }

 return 0;
}

##
# Checks if the given version is out of date relative to any of the given patched versions.
#
# if 'patches' contains multiple versions with the same major/minor/train, only the
# lowest one is compared against 'version'. e.g., if 'patches' contains
#
# 12.1(4)EA2, 12.1(4)EA5, 12.1(4)EA6
#
# the latter two versions are effectively ignored
#
# @param version IOS version to check
# @param patched a list of patched IOS versions to check for
# @param newest deprecated, ignored
# @param oldest the lower bound for vulnerable versions - versions 'oldest' and lower are not vulnerable (optional)
# @deprecated data from the IOS Software Checker tool should be used instead of this function whenever possible
#
# @return TRUE if 'version' is out of date with respect to 'patched',
#         FALSE otherwise
#
#         the patch used to determine 'version' is out of date is stored
#         in the global variable 'patch_update'
##
function check_release(version, patched, newest, oldest)
{
 local_var v, n, r;
 local_var vulnerable, not_vulnerable;
 patch_update = NULL;

 # having different booleans for vulnerable and non-vulnerable helps account for
 # situations where 'patched' contains multiple versions with the same
 # major/minor/train. 'version' may be out of date with respect to one, but not
 # another, meaning it is not vulnerable.
 vulnerable = 0;
 not_vulnerable = 0;

 # compare 'version' to each item in 'patched'. only like
 # "branches" (same major/minor/train) are compared
 for ( n = 0; n < max_index(patched) ; n ++ )
 {
  v = patched[n];
  r = cmp_version(version, v);

  # only compare versions if their major/minor/train is the same
  if ( r == 0 )
	{
	 r = cmp_release(version, v);
  	 if ( r < 0 )
		{
		 vulnerable = 1;
                 if (isnull(patch_update)) patch_update = v;
		}	
	 else
		{
                 # if the release numbers are the same, compare train/build
		 if ( r == 0 ) 
		 {
		  r = cmp_build(version ,v);

                  # the 'no_build' global is set when either 'version' or 'v'
                  # do not contain a train/interim build number
		  if ( no_build == 0 )
		  { 
		   if ( r < 0 )
                   {
                     vulnerable = 1;
                     if (isnull(patch_update)) patch_update = v;
                   }
		   else not_vulnerable = 1; 
		  }
	 	 }
		}
	}
 }

 if ( vulnerable && ! not_vulnerable )
 {
  # if 'version' is identified as vulnerable and a lower bound ('oldest') is provided,
  # make sure it doesn't come in under the lower bound
  if ( ! isnull(oldest) &&
       cmp_version(oldest, version) == 0 &&
       ( cmp_release(oldest, version) > 0 ||
       ( cmp_release(oldest, version) == 0 && cmp_build(oldest, version) > 0 ) ) )
  {
    return 0;
  }

  return 1;
 }
 else
   return 0;
}

##
# checks if the given ASA version 'version' is out of date
# (relative to 'patched').  a comparison is only performed
# when both major versions are the same. e.g.
#
# 1.2(3.4) and 1.2(5.6) will be compared, but
# 1.2(3.4) and 5.6(7.8) are not (function returns FALSE)
#
# it appears the versions published in Cisco's security advisories
# will have dots inside of the parenthesis, even though the versions
# on the actual devices are never expressed like this. the following
# example refers to the same version of the software
#
# advisory: 8.3(2.13)
# show ver: 8.3(2)13
#
# this function accounts for when 'version' and/or 'patched' is in
# either format
#
# @param  version  installed version to compare
# @param  patched  patched version to compare
#
# @return TRUE if the system needs to be updated to 'patched'
#         FALSE otherwise
##
function check_asa_release(version, patched)
{
 local_var major, patched_major;
 local_var minor, patched_minor;

 # only compare versions from the same major release
 major = ereg_replace(pattern:"^([0-9.]+).*", replace:"\1", string:version);
 patched_major = ereg_replace(pattern:"^([0-9.]+).*", replace:"\1", string:patched);
 if (major != patched_major) return FALSE;

 # rebuild the installed version to compare, e.g.
 # x.y(a.b)c becomes a.b.c
 # x.y(a.b) becomes a.b.0
 # x.y(a)b becomes a.b.0
 minor = eregmatch(pattern:"^[0-9.]+\(([0-9.]+\)([0-9]+)?).*", string:version);
 if (isnull(minor)) minor = '0.0';
 else
 {
   minor = minor[1];
   minor = str_replace(string:minor, find:')', replace:'.');
   if (minor[strlen(minor) - 1] == '.')
     minor = strcat(minor, '0');
 }

 # rebuild the patched version to compare, e.g.
 # x.y(a.b)c becomes a.b.c
 # x.y(a.b) becomes a.b.0
 # x.y(a)b becomes a.b.0
 patched_minor = eregmatch(pattern:"^[0-9.]+\(([0-9.]+\)([0-9]+)?).*", string:patched);
 if (isnull(patched_minor)) patched_minor = '0.0';
 else
 {
   patched_minor = patched_minor[1];
   patched_minor = str_replace(string:patched_minor, find:')', replace:'.');
   if (patched_minor[strlen(patched_minor) - 1] == '.')
     patched_minor = strcat(patched_minor, '0');
 }

 return ver_compare(ver:minor, fix:patched_minor, strict:FALSE) == -1;
}


##
# determines if the given version is part of the given deprecated train.
# e.g., if '12.1(14)EA4' and '12.1EA' are provided, returns TRUE (compares 12.1EA and 12.1EA)
#       if '12.1(14)EA' and '12.1AA' are provided, returns FALSE (compares 12.1EA and 12.1AA)
#
# @anonparam version IOS version to check
# @anonparam deprecated_train deprecated train to check for.
#                             this should not be a complete IOS version, it should only be the release train number and ID (e.g., 12.1EA)
#                             multiple arguments can be provided (positional parameters 1 through n)
#
# @return TRUE if 'version' is in the 'deprecated_train' train,
#         FALSE otherwise
##
function deprecated_version()
{
 local_var array,s,n;
 array = eregmatch(pattern:"([0-9.]*)\([0-9a-z.]*\)([A-Z]*)[0-9]*", string:_FCT_ANON_ARGS[0]);
 s = string(array[1], array[2]);

 for ( n = 1 ; _FCT_ANON_ARGS[n] ; n ++ )
 {
  if ( s == _FCT_ANON_ARGS[n] )
	return 1; 
 }

 return 0;
}

##
# Compares two strings representing versions. (assumes the strings are "." delimited.
#
# @param a     The first version string.
# @param b     The second version string.
#
# @return -1 if ver < fix, 0 if ver == fix, or 1 if ver > fix.
##
function cisco_gen_ver_compare(a, b)
{
  local_var afield, bfield, alen, blen, len, i;
  # replace ( and ) with dots to make comparisons more accurate
  a = ereg_replace(pattern:'[()]', replace:".", string:a);
  b = ereg_replace(pattern:'[()]', replace:".", string:b);
  # Break apart the version strings into numeric fields.
  a = split(a, sep:'.', keep:FALSE);
  b = split(b, sep:'.', keep:FALSE);
  # Both versions must have the same number of fields when
  # when doing a strict comparison.
  alen = max_index(a);
  blen = max_index(b);
  len = alen;
  if (blen > len) len = blen;
  # Compare each pair of fields in the version strings.
  for (i = 0; i < len; i++)
  {
    if (i >= blen) bfield = 0;
    else bfield = b[i];
    if (i >= alen) afield = 0;
    else afield = a[i];
    if ( (int(bfield) == bfield) && (int(afield) == afield) )
    {
      afield = int(a[i]);
      bfield = int(b[i]);
    }
    if (afield < bfield) return -1;
    if (afield > bfield) return 1;
  }
  return 0;
}

