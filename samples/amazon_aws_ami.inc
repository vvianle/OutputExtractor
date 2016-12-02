#TRUSTED 86c8c371d1abab205dc24c29745095218752700a4bab0f168e5c4fcfd30abe12b5e2cd73f0b1977532c54cb7c26119f33d981e062494be32519e7680f74770acfefff34db8b5cbfe37beeb3399082081f197261e158e0130010a8b05f045a5657367bd5c1f5037525fff3e7df3ab62f393dcd2c48cb234a5ed8186dce8352baec32af26630d0362e918d00ac4fff106c578f7c18fcb307cb520710363ce999249c189079d3dff524cd0a55664c6571933b38c50e740b9c59a9ef7b412a7420129eb8e2ce6b8725b90a9e1f38c0fe35fb1a5df87fc4479821f76772bde575b1c48018027f1451efab258a0a900afb3e7107156af1892ac775bbc50b69ba47b66f112d4d6dd0a6af80c3bc94acffed8fca5d27096093b29c57e6b4053bd6cd5af273f53dcf3eee3e35f871c3cf9a6cd263d8d6c5cf89189d2a7aa97d71e67f449bdabc8e1dd98fc8482a5332b46491c528d9490b921634f74cece8211c7af2510d105cf3088a057c1f1a917e7df58e8b36605d7da6b7194973f44a9142002ec3234d1ae55f9962589ac8af9640ee2c8b224f0b7616143d7bd3299b05b4558012111f70d74ae77f44d3ed9971da7c635ff34d45ee53ffdc758654a7fd9d2bf7e53a17a4cbd94cb3db9915a8923062a83f00d1b4e0436f208af4c3c582e981324e927d72e9f8c528b8b0e6da8e256ae94fd9dcce020746b14bd27d5fecd53612eab4
#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# amazon_aws_ami.inc
# Revision: 1.0
#

global_var AWS_AMI_API_ROOT,AWS_AMI_API_HOST,AWS_AMI_API_ITEMS,AWS_AMI_HOST_TAG_BASE,AWS_AMI_KB_BASE;

##
# AMI API Root
##
AWS_AMI_API_ROOT  = "/latest/meta-data/";

##
# AMI API Host
##
AWS_AMI_API_HOST  = "169.254.169.254";

##
# XML Host Tag base
##
AWS_AMI_HOST_TAG_BASE = "aws-instance";

##
# KB Base
##
AWS_AMI_KB_BASE = "Host/AWS/AMI";

##
# API Items with their validation regular expressions
##
AWS_AMI_API_ITEMS = make_array(
  'ami-id'         , "^ami-[A-Za-z0-9]+$",
  'instance-id'    , "^i-[A-Za-z0-9]+$",
  'hostname'       , "^[A-Za-z\-0-9.]+$",
  'local-hostname' , "^[A-Za-z\-0-9.]+$",
  'public-hostname', "^[A-Za-z\-0-9.]+$",
  'local-ipv4'     , "^\d+\.\d+\.\d+\.\d+$",
  'public-ipv4'    , "^\d+\.\d+\.\d+\.\d+$"
);
