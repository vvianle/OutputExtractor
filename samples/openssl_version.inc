#TRUSTED 81c862ba4c969fcfb2e846175de442e93b50e2e011f7fc84d4e4aa27c0b8a8a8b84d16e0bc895622002953ea4b619bee9277023b5b1521851a3bded8c73c8fe02ae6588bbc113e382d151b12257e1a37a2edc65b4596314e33ca92e28e422c95a30064c757ea10d55a478dd0ec09ef654e432aceb634f61ea36866707ee8290369fb86463986eb4857270ad4dbab8b272e97b5298cef35398eceb5798d648ba2dfb816d73ecfb0478719bef70615a7b3403147f6e5459051cbedb728788580b4df196dcf5ef136171d63015fe2096be75c237b5cfc85ab9d4116e63d297b5234c38ccea7003b8f7e229711aa56c026bd9b9ee29e646886d506ab73641708b03af1b9f2c2e01c4f346dea5d27c7c7a3451f2405b8744a4d8e25d718028af8ddd110c4eba47c556c4ac16dc8acc349712036f27ffeccf6463d9a25a6f186ad71522efdda5cafa38d3cc83dba0c31409ba02d56b0980f5658ad072ac21e209da2ff1931fcafe3becdc1b3748a8c80ec97dc2e03ae590e2bda6420f3e24d5189ba97f174faf0543085b08beb0fbfdaa897c87571aa2e0a89362e2b710b987ce7c4b8a3dad70ff922196cd8ad5decebbbc0bb990fb154385fe318c85df3f02f6ff0d50e84116e99e72e460c732fe96a728e9610e982f2ce9136ceaafdb73e00f8b988d0e8f4ceee8eb9ffead345c6868964f38c8a78d84c4269120431229562bb1bec
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "OpenSSL";

# compares two OpenSSL versions. each version must be all numeric and
# can end with a letter, optionally with a beta version number
# e.g. 0.9.6e
# or   1.0.0-beta1
#
# Additional text like -fips or -rhel5 is erased & ignored currently.
#
# args: ver, fix - versions to compare
#
# returns -1	if ver < fix
#          0	if ver == fix
#          1	if ver > fix
#	   NULL	error, invalid format
#
function openssl_ver_cmp(ver, fix, same_branch, is_min_check)
{
  local_var	pat, vv, ff, i, v, f;

  # Do not anchor on the right, version might be "0.9.8e-fips-rhel5"
  pat = '^([0-9]+)\\.([0-9]+)\\.([0-9]+)([a-z]+)?((-fips)?(-beta([0-9]+))?)?';

  vv = eregmatch(string: ver, pattern: pat, icase: FALSE);
  if (isnull(vv))
  {
    err_print('openssl_ver_cmp: invalid version ver=', ver);
    return NULL;
  }

  ff = eregmatch(string: fix, pattern: pat, icase: FALSE);
  if (isnull(ff))
  {
    err_print('openssl_ver_cmp: invalid version fix=', fix);
    return NULL;
  }

  for (i = 1; i <= 3; i ++)
  {
    v = int(vv[i]);
    f = int(ff[i]);
    if (same_branch)
    {
      if (v != f) return 0;
    }
    else
    {
      if (v < f) return -1;
      if (v > f) return 1;
    }
  }

  # a < z is safe
  # z < za is safe
  # za < zz is safe
  v = vv[4];
  f = ff[4];
  if (v < f) return -1;
  if (v > f) return 1;

  if (! isnull(vv[8]) || ! isnull(ff[8]))
  {
    v = int(vv[8]); f = int(ff[8]);
    if (v != f)
    {
      # No beta is newer than betaXXX

      # In a min_check, betas are not vuln
      if (is_min_check)
      {
        if (v == 0) return -1;
        if (f == 0) return 1;
      }
      else
      {
        # In a normal check, betas are vuln
        if (v == 0) return 1;
        if (f == 0) return -1;
      }

      if (v < f) return -1;
      if (v > f) return 1;
    }
  }
  return 0;
}

####

global_var	port, ver;

##
# Checks if server's OpenSSL version is vulnerable.
#
# @param  list   fixed list of fixed versions
# @param  int    severity reporting severity
# @param  string min minimum vulnerable version
#
# @remark This function does not return, it either reports or exits.
##
function openssl_check_version(fixed, severity, min)
{
  local_var port;
  local_var kb_base;
  local_var banner, version, backported;
  local_var fix, same_branch;
  local_var report;

  report = '';

  # Make sure OpenSSL is installed.
  port = get_kb_item("openssl/port");
  if (isnull(port)) audit(AUDIT_NOT_INST, app_name);

  # Get relevant data for installed version.
  kb_base = "openssl/" + port + "/";
  banner = get_kb_item(kb_base + "pristine_banner");
  version = get_kb_item(kb_base + "pristine_version");
  backported = get_kb_item(kb_base + "backported");

  # If the banner is backported, and we're not running a paranoid
  # scan, audit out.
  if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, app_name);

  # Make sure the version is above the min vuln version.
  if (!isnull(min) && openssl_ver_cmp(ver:version, fix:min, same_branch:FALSE, is_min_check:TRUE) < 0)
    audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

  # Check against list of fixes.
  fixed = make_list(fixed);
  if (len(fixed) > 1) same_branch = TRUE;
  else same_branch = FALSE;

  foreach fix (fixed)
  {
    if (openssl_ver_cmp(ver:version, fix:fix, same_branch:same_branch) < 0)
    {
      report =
        '\n  Banner           : ' + banner +
        '\n  Reported version : ' + version +
        '\n  Fixed version    : ' + fix;

      if (backported) report +=
        '\n\nBased on the banner, security patches may have been backported to' +
        '\nthis install of OpenSSL. A local check is needed to confirm the' +
        '\npresence of this vulnerability.';

      report += '\n';
      security_report_v4(port:port, severity:severity, extra:report);
      exit(0);
    }
  }

  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
}

# Local Variables:
# mode:Fundamental
# End:
