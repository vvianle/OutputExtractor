#TRUSTED a70de8e8a18feb1a93884c579954b9917270a826c4f8fb6b42411516ffcb8be08b23bd5a8bd5a55e2dc02ae59c9d249d5b926c02ffc830a078c5f0e48006fb458d52c0e98ac8e08ae28d19c3eaad1dab261fc862c0c5c2e8d6c53d34487e7fb17ee8f7ff1dc84f5020b33986b1684f9d438a63231d186dc53d33c7062714b20c89cdfe30ae0e29d5373ddf2bac492203055808eeb8d4f04856f5c8669e43b6f45402cf9561d372757a1eebc3a84d5e2196d32c12095b91df4de46ab1badb42c54d3596453b414462fc05db551955123688aa4bbaa6d7b30a1837e9a0ef1c5d04ab36fcc76b309b345a5e54c4d5c77a4b7056a5610e6cf7a327d80910397cc78d6c3a3707834fa4b90f2b9690f7e384d29b85ea5f54f9a92c07c2664c2de8d2e9a74df6e33fc45b16f1af72e307838efd5603d2ee1e33cddd46937afa71b19561255dc631516789a7bd130479b423b9a685d68a1db64efba8278cffc2e774e7224b69f2724c5b6b556ca1aaf117fd7f5677e65492a1ab3e92071b4d9f21c4edc5f897c62ce141456ab8703eccfde89e4b5f03a5b2b7c23e8c1335de44c77047668484d2087c4492e89d885277f0e728c440d6c357c61e1572c3cc2c94e3390c430d7ffe7d94c4cc04039752dc776030c81bcffef627a761b65e27cfd60b4f9249199e065a198d7d99f317bd3f8efd7e67f0126c3715486c629a23a81e62cd2a40
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# xcompat.inc
# Revision 1.1

#
# Backward compatibility functions
#
__desc_buf = NULL;



function cvss_vector_to_temporal_score(vector, base_score)
{
 local_var str;
 local_var Exploitability, RemediationLevel, ReportConfidence;
 local_var base;
 local_var score;
 
 str = vector;
 base_score = split(base_score, sep:'.');
 base = int(base_score[0]) * 1000 + int(base_score[1]) * 100;

 if ( "E:U/" >< str )
     Exploitability = 1176; # 0.85
 else if ( "E:POC/" >< str )
     Exploitability = 1111; # 0.9 
 else if ( "E:F/" >< str )
     Exploitability = 1052; # 0.95
 else if ( "E:H/" >< str )
     Exploitability = 1000; # 1.00
 else #if ( "E:/" >< str || "E:ND/" >< str )
     Exploitability = 1000; # 1.00

 if ( "/RL:OF/" >< str )
     RemediationLevel = 1149; # 0.87
 else if ( "/RL:TF/" >< str )
     RemediationLevel = 1111; # 0.90
 else if ( "/RL:W/" >< str )
     RemediationLevel = 1052; # 0.95
 else if ( "/RL:U/" >< str )
     RemediationLevel = 1000; # 1.00
 else #if ( "/RL:/" >< str || "/RL:ND/" >< str )
     RemediationLevel = 1000; # 1.00

 if ( "/RC:UC" >< str )
     ReportConfidence = 1111; # 0.90 
 else if ( "/RC:UR" >< str )
     ReportConfidence = 1052; # 0.95
 else if ( "/RC:C" >< str )
     ReportConfidence = 1000; # 1.00
 else #if ( "/RC:" >< str || "/RC:ND" >< str )
     ReportConfidence = 1000; # 1.00

 
 score = (base  * 1000)/Exploitability;
 score = (score * 1000)/RemediationLevel;
 score = (score * 1000)/ReportConfidence;
 if ( score % 100 >= 50) score += ( 100 - (score % 100) ); # Rounding
 if ( score / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( score % 100 >= 40) score += ( 100 - (score % 100) ); 
 }
 
 score = (score/10)*10;
 return strcat(score / 1000, ".", (score % 1000)/100);
}

function cvss_vector_to_base_score()
{
 local_var str;
 local_var c,i,a;
 local_var AccessVector, AccessComplexity, Authentication;
 local_var q,z;
 local_var cvss_score;

 str = _FCT_ANON_ARGS[0];
 if ( "AV:L/" >< str )
   AccessVector = 2532;
 else if ( "AV:A/" >< str )
   AccessVector = 1548;
 else if ( "AV:N/" >< str)
   AccessVector = 1000;
 else 
 {
   #display("Unknown CVSS access subvector (", str, ")!\n");
   return NULL;
 }

 if ( "AC:L/" >< str )
   AccessComplexity = 1408;
 else if ( "AC:M/" >< str )
   AccessComplexity = 1639;
 else if ( "AC:H/" >< str )
   AccessComplexity = 2857;
 else 
 {
   #display("Unknown CVSS access complexity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "Au:N/" >< str )
   Authentication = 1420;
 else if ( "Au:S/" >< str )
   Authentication = 1786;
 else if ( "Au:M/" >< str )
   Authentication = 2222;
 else 
 {
   #display("Unknown CVSS authentication subvector (", str, ")!\n");
   return NULL;
 }

 if ( "C:N/" >< str )
   c = 1000;
 else if ( "C:P/" >< str )
   c = 725;
 else if ( "C:C/" >< str )
   c = 340;
 else 
 {
   #display("Unknown CVSS confidentiality subvector (", str, ")!\n");
   return NULL;
 }

 if ( "I:N/" >< str )
   i = 1000;
 else if ( "I:P/" >< str )
   i = 725;
 else if ( "I:C/" >< str )
   i = 340;
 else 
 {
   #display("Unknown CVSS integrity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "/A:N" >< str )
   a = 1000;
 else if ( "/A:P" >< str )
   a = 725;
 else if ( "/A:C" >< str )
   a = 340;
 else 
 {
   #display("Unknown CVSS availability subvector (", str, ")!\n");
   return NULL;
 }

 if ( c + i + a == 3000 )
   return "0.0";

 z = (c*1000)/( (1000*1000)/i);
 z = (z*1000)/( (1000*1000)/a);
 z = 1000 - z;
 z = (1000*1000)/z;
 z = (10410*1000)/z;
 z = (z*1000)/1666;

 q = ( AccessComplexity  * 1000 ) / (( 1000 * 1000 )/Authentication );
 q = ( q * 1000 ) / ( ( 1000 * 1000 ) / AccessVector );
 q = ( 1000 * 1000 ) / q;
 q = q * 20000;
 q = q / 2500;

 z = ( z + q ) - 1500;
 z = (z * 11760)/10000;
 if ( z % 100 >= 50) z += ( 100 - (z % 100) ); # Rounding
 if ( z / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( z % 100 >= 40) z += ( 100 - (z % 100) ); 
 }
 
 z = (z/10)*10;
 cvss_score = strcat(z / 1000, ".", (z % 1000)/100);
 return cvss_score;
}



function xscript_set_attribute(attribute, value)
{
 local_var s, e;
 local_var i;

 if ( defined_func("script_set_attribute") )
 {
  script_set_attribute(attribute:attribute, value:value);
  return;
 }
 if ( isnull(attribute) || isnull(value) ) return;
 value = '' + value;
 e = strlen(value);
 for ( i = 0 ; value[i] >< ' \t\n\r' && i < e ; i ++ ) { };
 for ( e = strlen(value) - 1; value[e] >< ' \t\n\r' && e > 0 ; e -- ) { };
 value = substr(value, i, e);
 if ( strlen(__desc_buf[attribute]) ) __desc_buf[attribute] += '\n';
 __desc_buf[attribute] += value;
}


function xscript_set_cvss_base_vector()
{
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 xscript_set_attribute(attribute:"cvss_vector", value:vec);
 if ( NASL_LEVEL < 4300 )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(vec);
}

function xscript_set_cvss_temporal_vector()
{
 local_var base_score;
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 xscript_set_attribute(attribute:"cvss_temporal_vector", value:vec);

 if ( NASL_LEVEL < 4300 )
 {
  base_score = __desc_buf["cvss_base_score"];
  if ( ! isnull(base_score) )
   xscript_set_attribute(attribute:"cvss_temporal_score", value:cvss_vector_to_temporal_score(vector:vec, base_score:base_score));
 }
}

function xscript_end_attributes()
{
 local_var r;
 local_var buf;

 if ( defined_func("script_end_attributes") )
 {
  script_end_attributes();
  return;
 }

 if ( isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_vector"]) )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(__desc_buf["cvss_vector"]);


 if ( isnull(__desc_buf["risk_factor"]) )
 {
  if ( isnull(__desc_buf["cvss_base_score"]) )
	__desc_buf["risk_factor"] = "None";
  else {
   if ( int(__desc_buf["cvss_base_score"]) == 10 ) __desc_buf["risk_factor"] = "Critical";
   else if ( int(__desc_buf["cvss_base_score"]) >= 7 ) __desc_buf["risk_factor"] = "High";
   else if ( int(__desc_buf["cvss_base_score"]) >= 4 ) __desc_buf["risk_factor"] = "Medium";
   else if ( int(__desc_buf["cvss_base_score"]) > 0 ) __desc_buf["risk_factor"] = "Low";
   else __desc_buf["risk_factor"] = "None";
  }
 }



 buf = "";
 r = __desc_buf["synopsis"];
 if ( strlen(r) )
 {
   buf += 'Synopsis :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["description"];
 if ( strlen(r) )
 {
   buf += 'Description :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["see_also"];
 if ( strlen(r) )
 {
   buf += 'See also :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["solution"];
 if ( strlen(r) )
 {
   buf += 'Solution :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["risk_factor"];
 if ( strlen(r) )
 {
   buf += 'Risk factor :\n\n';
   buf += r;
   r = __desc_buf["cvss_base_score"];
   if ( r ) {
	buf += " / CVSS Base Score : " + r;
	r = __desc_buf["cvss_vector"];	
	if ( r ) buf += '\n(' + r + ')\n';
    	else buf += '\n';
    }
    else buf += '\n';
 }
 
 if ( NASL_LEVEL < 3000 && strlen(buf) >= 3000 )
   buf = strcat(substr(buf, 0, 3000), "...");

 script_description(buf);
}

function xscript_osvdb_id()
{
  local_var	i;

  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"OSVDB", value: i);
}

function xscript_cwe_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"CWE", value: i);
}

function xscript_cvs_date()
{
  local_var	v;

  v = split(_FCT_ANON_ARGS[0], sep: ' ', keep: 0);
  if ( isnull(v) || isnull(v[1]) || v[1] !~ "^2[0-9]+/[0-9]+/[0-9]+$" ) return;
  xscript_set_attribute(attribute:"plugin_modification_date", value: v[1]);
}
