###
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
# charset_func.inc
# $Revision: 1.6 $
###


EBCDIC_CHAR_CODE_SET_ID_819 = raw_string(      # default on most systems using EBCDIC.
  0000, 0001, 0002, 0003, 0234, 0011, 0206, 0177, 0227, 0215, 0216, 0013, 0014, 0015, 0016, 0017,
  0020, 0021, 0022, 0023, 0235, 0205, 0010, 0207, 0030, 0031, 0222, 0217, 0034, 0035, 0036, 0037,
  0200, 0201, 0202, 0203, 0204, 0012, 0027, 0033, 0210, 0211, 0212, 0213, 0214, 0005, 0006, 0007,
  0220, 0221, 0026, 0223, 0224, 0225, 0226, 0004, 0230, 0231, 0232, 0233, 0024, 0025, 0236, 0032,
  0040, 0240, 0342, 0344, 0340, 0341, 0343, 0345, 0347, 0361, 0242, 0056, 0074, 0050, 0053, 0174,
  0046, 0351, 0352, 0353, 0350, 0355, 0356, 0357, 0354, 0337, 0041, 0044, 0052, 0051, 0073, 0254,
  0055, 0057, 0302, 0304, 0300, 0301, 0303, 0305, 0307, 0321, 0246, 0054, 0045, 0137, 0076, 0077,
  0370, 0311, 0312, 0313, 0310, 0315, 0316, 0317, 0314, 0140, 0072, 0043, 0100, 0047, 0075, 0042,
  0330, 0141, 0142, 0143, 0144, 0145, 0146, 0147, 0150, 0151, 0253, 0273, 0360, 0375, 0376, 0261,
  0260, 0152, 0153, 0154, 0155, 0156, 0157, 0160, 0161, 0162, 0252, 0272, 0346, 0270, 0306, 0244,
  0265, 0176, 0163, 0164, 0165, 0166, 0167, 0170, 0171, 0172, 0241, 0277, 0320, 0335, 0336, 0256,
  0136, 0243, 0245, 0267, 0251, 0247, 0266, 0274, 0275, 0276, 0133, 0135, 0257, 0250, 0264, 0327,
  0173, 0101, 0102, 0103, 0104, 0105, 0106, 0107, 0110, 0111, 0255, 0364, 0366, 0362, 0363, 0365,
  0175, 0112, 0113, 0114, 0115, 0116, 0117, 0120, 0121, 0122, 0271, 0373, 0374, 0371, 0372, 0377,
  0134, 0367, 0123, 0124, 0125, 0126, 0127, 0130, 0131, 0132, 0262, 0324, 0326, 0322, 0323, 0325,
  0060, 0061, 0062, 0063, 0064, 0065, 0066, 0067, 0070, 0071, 0263, 0333, 0334, 0331, 0332, 0237
);
EBCDIC_CHAR_CODE_SET_ID_1047 = raw_string(     # default on OS390 systems.
  0000, 0001, 0002, 0003, 0234, 0011, 0206, 0177, 0227, 0215, 0216, 0013, 0014, 0015, 0016, 0017,
  0020, 0021, 0022, 0023, 0235, 0012, 0010, 0207, 0030, 0031, 0222, 0217, 0034, 0035, 0036, 0037,
  0200, 0201, 0202, 0203, 0204, 0205, 0027, 0033, 0210, 0211, 0212, 0213, 0214, 0005, 0006, 0007,
  0220, 0221, 0026, 0223, 0224, 0225, 0226, 0004, 0230, 0231, 0232, 0233, 0024, 0025, 0236, 0032,
  0040, 0240, 0342, 0344, 0340, 0341, 0343, 0345, 0347, 0361, 0242, 0056, 0074, 0050, 0053, 0174,
  0046, 0351, 0352, 0353, 0350, 0355, 0356, 0357, 0354, 0337, 0041, 0044, 0052, 0051, 0073, 0136,
  0055, 0057, 0302, 0304, 0300, 0301, 0303, 0305, 0307, 0321, 0246, 0054, 0045, 0137, 0076, 0077,
  0370, 0311, 0312, 0313, 0310, 0315, 0316, 0317, 0314, 0140, 0072, 0043, 0100, 0047, 0075, 0042,
  0330, 0141, 0142, 0143, 0144, 0145, 0146, 0147, 0150, 0151, 0253, 0273, 0360, 0375, 0376, 0261,
  0260, 0152, 0153, 0154, 0155, 0156, 0157, 0160, 0161, 0162, 0252, 0272, 0346, 0270, 0306, 0244,
  0265, 0176, 0163, 0164, 0165, 0166, 0167, 0170, 0171, 0172, 0241, 0277, 0320, 0133, 0336, 0256,
  0254, 0243, 0245, 0267, 0251, 0247, 0266, 0274, 0275, 0276, 0335, 0250, 0257, 0135, 0264, 0327,
  0173, 0101, 0102, 0103, 0104, 0105, 0106, 0107, 0110, 0111, 0255, 0364, 0366, 0362, 0363, 0365,
  0175, 0112, 0113, 0114, 0115, 0116, 0117, 0120, 0121, 0122, 0271, 0373, 0374, 0371, 0372, 0377,
  0134, 0367, 0123, 0124, 0125, 0126, 0127, 0130, 0131, 0132, 0262, 0324, 0326, 0322, 0323, 0325,
  0060, 0061, 0062, 0063, 0064, 0065, 0066, 0067, 0070, 0071, 0263, 0333, 0334, 0331, 0332, 0237
);


##
# Converts an ASCII string to EBCDIC
#
# @param str ASCII string to convert
# @param ccsid CCSID (EBCDIC character set) to convert to
#
# @return EBCDIC representation of 'str'
##
function ascii2ebcdic(str, ccsid)
{
  if (isnull(str)) return NULL;

  local_var c, i, l, res, table;
  l = strlen(str);

  if (ccsid == 1047) table = EBCDIC_CHAR_CODE_SET_ID_1047;
  else table = EBCDIC_CHAR_CODE_SET_ID_819;

  res = "";
  for (i=0; i<l; i++)
  {
    c = str[i];
    res += raw_string(stridx(table, c));
  }
  return res;
}

##
# Converts an EBCDIC string to ASCII
#
# @param str EBCDIC string to convert
# @param ccsid CCSID (character set) of 'str'
#
# @return ASCII representation of 'str'
##
function ebcdic2ascii(str, ccsid)
{
  if (isnull(str)) return NULL;

  local_var c, i, l, res, table;
  l = strlen(str);

  if (ccsid == 1047) table = EBCDIC_CHAR_CODE_SET_ID_1047;
  else table = EBCDIC_CHAR_CODE_SET_ID_819;

  res = "";
  for (i=0; i<l; i++)
  {
    c = ord(str[i]);
    res += table[c];
  }
  return res;
}


##
# Bool check if an item is within printable
# ascii range
#
# @param [char:char] the character to check
#
# return bool True if printable
##
function is_ascii_printable(char)
{
  local_var c;

  # Accept argument anonymously.
  if (isnull(char)) char = _FCT_ANON_ARGS[0];
  if (isnull(char))
  {
    err_print("is_ascii_printable(): missing required arg 'char'");
    return FALSE;
  }

  if (strlen(char) != 1) return FALSE;

  # 9=TAB, 10=LineFeed, 13=CarriageReturn
  # 32-126(0x20-0x7E) is the ascii printable range
  if (((ord(char) > 31) && (ord(char) < 127)) ||
       (ord(char) == 9) || (ord(char) == 10) ||
       (ord(char) == 13) )
  {
    return TRUE;
  }

  return FALSE;
}

##
# remove all non-printable chars from a string
#
# @param [string:string] string to parse
#
# @return string the ascii printable clean string
#
# @remark Because the string is passed by value
#    and not ref, nullbytes will cut the string
#    down. This function should not be used to
#    strip out null bytes. Use the example here.
#    example: if (var[i] == raw_string(0))
##
function get_ascii_printable(string)
{
  local_var asciiString, stringLen, i;

  stringLen = strlen(string);
  asciiString = "";
  for (i=0;i<stringLen;i++)
  {
    # 9=TAB, 10=LineFeed, 13=CarriageReturn
    # 32-126(0x20-0x7E) is the ascii printable range
    if (((ord(string[i]) > 31) && (ord(string[i]) < 127)) ||
         (ord(string[i]) == 9) || (ord(string[i]) == 10) ||
         (ord(string[i]) == 13) )
    {
      asciiString += string[i];
    }
  }

  return asciiString;
}

##
#
##
function hex2str(badchars)
{
  local_var xlat,hs,s,i,j, hx;

  hs=_FCT_ANON_ARGS[0];
  s="";

  for (i=0; i<256; ++i) xlat[substr(hex(i),2)]=raw_string(i);

  for (j=0; j<strlen(hs)/2; ++j)
  {
    hx = substr(hs,2*j,2*j+1);
    if (!isnull(badchars[hx]))
    {
      s += badchars[hx];
      continue;
    }

    s += xlat[hx];
  }

  return s;
}