##
#
# @return one of:
#   PRODUCT_WIN_AGENT     - Windows agent
#   PRODUCT_UNIX_AGENT    - Unix agent
#   PRODUCT_NESSUSD       - Normal nessusd
#   PRODUCT_NESSUSD_NSX   - Nessusd in NSX environment
#   NULL - nessusd product undetermined
# 
# @remark
#   Someone suggest a better name
##
function nessusd_product()
{
  local_var env;

  if(defined_func("nasl_environment"))
  {
    env   = nasl_environment();
    return env["product"];
  }

  # older nussusd  
  return NULL; 
}

##
#
##
function nessusd_is()
{
  local_var prod, target;
 
  target = _FCT_ANON_ARGS[0];
  if(isnull(target)) return FALSE;
 
  prod = nessusd_product();

  return (prod == target);
}

##
#
##
function nessusd_is_win_agent()
{
  return nessusd_is(PRODUCT_WIN_AGENT);
}

##
#
##
function nessusd_is_unix_agent()
{
  return nessusd_is(PRODUCT_UNIX_AGENT);
}

##
#
##
function nessusd_is_nsx()
{
  return nessusd_is(PRODUCT_NESSUSD_NSX);
}


##
# Is nessusd run in agent mode? 
##
function nessusd_is_agent()
{
  local_var prod;
  
  prod = nessusd_product();
  
  if( !isnull(prod) &&
      (prod == PRODUCT_WIN_AGENT 
        || prod == PRODUCT_UNIX_AGENT
        # || prod == PRODUCT_NESSUSD_NSX  # Nessusd in NSX is an agent?
      )
   ) return TRUE;

  return FALSE;
}

##
# Is nessusd used in a local scan environment?
# @todo add in local_host() to the check
##
function nessusd_is_local()
{
  local_var prod;

  prod = nessusd_product();
  
  if( !isnull(prod) &&
     ( prod == PRODUCT_WIN_AGENT 
     || prod == PRODUCT_UNIX_AGENT
     || prod == PRODUCT_NESSUSD_NSX 
     || islocalhost()
    )
   ) return TRUE;

  return FALSE;
}
