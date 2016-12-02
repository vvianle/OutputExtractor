#TRUSTED 87b311d977d0958efbb095ae509d1afab5e33d4118c7dbaa8a8abd50989b91f4c9d7d9f1ff7084a372adb9db5b4f49bb25ea1eb413bfdde46e7c73baf914c069c965cc71eda1c6f3beb7205a58e030fa8f3875959b371670b25e29bc523c1ca0be91db90086b5df01f73acc1a307183006a0c378807bb41787d1072bc3c1d24c5dfa9b89497a5cad3283230a5d6c15330be1f2ae7e74eab44e1d75e092e0cba325cd066e84e0dfe41b49b6a10f182156e3c1c5dd0bd2225fb63b6e987d1b5cc96b4a1454edf68f00b569523877fccc23d6ee1b7d1ab8cd5f3faea0fcd4414f6076d2c07afb59c707edd3592a12b3f075b870b2ca6be09b5d3fc4bc6cbcf3879dd33c9610a4bfae1aedc76b3a7c2888d8d8cb25b69a60c3f3002519561cc5a4b17f649abbfd90f24bd217bf39417eda46c623d3adef8a2a2124543d3184b85f4b6b023d69be7c2bec6787b4c7e4ca205f427d367457c02e3cf54b26232f96376e10eb2d7b1d44b57b777edf39174b518b71b7bdd909bcda43cf05e2da69c882cf69909369283bbf55087a48ef840d3b1666a32079b24e09313f0d5ee7a191a871b9b214ce1795bc96b3a572836a7aa48c7bd3b51e72814bfd5cc11eb80b0061c1fe2a6a2da1dbfdbe757cc717e04436d62213dc776a355ab65ba8bddda897d89f0229d97442ee6dc187a0f569897fd4dcc0b77739d42d60ab5318ac3e6f5f8767
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
# http_login.inc
# Revision: 1.7

global_var	CookieJar_is_disabled;
global_var	HttpLogin_reauthentication_OK, HttpLogin_reauthentication_KO;

function http_check_authentication(port, check_page, regex, re_invert, re_headers, re_icase, follow_redirect)
{
  local_var	r, s, flag;

  if (strlen(check_page) == 0 || strlen(regex) == 0) return "";

  r = http_send_recv3(method:"GET", item: check_page, port: port, follow_redirect: follow_redirect);
  if (isnull(r))
  {
    return strcat("request failed: GET ", check_page);
  }
  if (re_headers)
    s = egrep(string: r[0]+r[1], pattern: regex, icase: re_icase);
  else
    s = egrep(string: r[2], pattern: regex, icase: re_icase);
  flag = (strlen(s) > 0);
  if (flag)
    debug_print(level: 3, 'http_check_authentication extracted pattern: ', chomp(s));
  if (re_invert) flag = ! flag;
  if (! flag)
  {
    if (report_verbosity > 1)
      return strcat("post-authentication test failed", '.\nThe web server answered :\n\n', r[0], r[1], '\n', r[2]);
    else
      return strcat("post-authentication test failed");
  }
  return "OK";
}

# This function returns an empty string for "maybe", "OK" if authentication 
# succeeded (the control page could be check). Any other string is an error 
# message.
function http_form_login(port, page, form, fields, follow_redirect, 
	 		 save_cookies, check_page, regex, re_invert,
			 re_headers, re_icase, method)
{
  local_var	r, trp, h, e;

  h = make_array();
  e = "";

  if (page)
  {
    r = http_send_recv3(port: port, item: page, method: 'GET', follow_redirect: follow_redirect);
    if (isnull(r))
    {
      debug_print("Broken connection on port ", port, " after GET ", page);
      return strcat("request failed: GET ", page);
    }

    trp = get_port_transport(port);
    h["Referer"] = build_url(port: port, qs: page);
  }

  if (! method) method = "POST";

  if (method == "POST")
  {
  h["Content-Type"] = "application/x-www-form-urlencoded";
  r = http_send_recv3( port: port, method: 'POST', 
      		       follow_redirect: follow_redirect,
      		       add_headers: h, 
    		       item: form, data: fields);
  }
  else
  {
    r = http_send_recv3( port: port, method: 'GET', 
      		       follow_redirect: follow_redirect,
    		       item: form + "?" + fields);
  }
  if (isnull(r))
  {
    debug_print("Broken connection on port ", port, " after ", method, " ", form);
    return strcat("request failed: ", method, " ", form);
  }

  # Failed - permission denied or bad gateway or whatever
  # This happens sometimes when we follow redirections, but we might be 
  # authenticated anyway.
  if (r[0] =~ "^HTTP/[01.]+ +[45][0-9][0-9] ")
  {
    debug_print("Permission denied: code=", r[0]);
    e =  "Permission denied or other HTTP error on "+method+" request";
  }
  # All other codes are considered as OK. We might get a 30x code too!

  r = http_check_authentication(port: port, check_page: check_page, regex: regex, re_invert: re_invert, re_headers: re_headers, re_icase: re_icase, follow_redirect: follow_redirect);

  if (r == "")
  {
    # We could not check if we are authenticated but we got an error first. 
    # Let's return it.
    if (e != "") return e;
  } else if (r != "OK")	# Error
    return r;

  # Here, we are sure that we are authenticated (OK) 
  # or nothing proves that we are not.
  if (! CookieJar_is_disabled && save_cookies) store_cookiejar("FormAuth");
  return r;
}


function http_login_take_lock(port, now, delay)
{
  local_var	k, t, v;

  if (NASL_LEVEL < 3000) return 1;	# Cannot work

  k = "/tmp/http_login/"+port+"/lock";
  t = get_kb_item(k);
  if (t)
  {
    v = split(t, sep:'-', keep: 0);
    t = now - int(v[0]);
    if (t > delay || t < 0)
    {
      debug_print("http_login_take_lock: old lock (", t, " s ago) deleted (port=", port, ")");
      rm_kb_item(name:k);
    }
    else
    {
      debug_print(level: 2, "http_login_take_lock: lock taken ", t, " s ago");
      return 0;
    }
  }
  v = strcat(now, '-', rand());
  replace_kb_item(name:k, value: v);

  if (get_kb_item(k) != v)
  {
    debug_print("http_login_take_lock: lock stolen");
    return 0;
  }
  return 1;
}

function http_login_release_lock()
{
  local_var	k, port;
  if (NASL_LEVEL < 3000) return 1;	# Cannot work
  port = _FCT_ANON_ARGS[0];
  k = "/tmp/http_login/"+port+"/lock";
  rm_kb_item(name: k); 
  return 1;
}


# This function should only be called if a lock has been taken
function http_login_incr_count(port, kb)
{
  local_var	k, n;

  k = "www/"+port+"/"+kb;
    n = get_kb_item(k);
    n ++;
    replace_kb_item(name: k, value: n);
  }

function http_reauthenticate_if_needed(port, save_cookies)
{
  local_var	page, form, fields, time, e, delay, now;
  local_var	cp, re, iv, hd, ic, fr, i, mt;

  cp = get_kb_item("www/"+port+"/check_page");
  re = get_kb_item("www/"+port+"/check_regex");
  iv = get_kb_item("www/"+port+"/regex_invert");
  hd = get_kb_item("www/"+port+"/regex_headers");
  ic = get_kb_item("www/"+port+"/regex_icase");
  fr = get_kb_item("www/"+port+"/login_follow_30x");

  e = http_check_authentication(port: port, check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic, follow_redirect: fr);
  if (e == "OK") return;

  # Ideally, we should take a mutex here, but the functions are privileged
  # and we do not want to sign all web scripts.

  if (e != "")		# use a tiny delay if we are disconnected
    delay = get_read_timeout();
  else
    delay = get_kb_item("www/"+port+"/login_delay");
  if (delay <= 0) return;

    time = get_kb_item("www/"+port+"/login_time");
  now = unixtime();
  if (time + delay > now)
    {
    debug_print(level: 2, 'Will not try to re-authenticate on port ', port, ' before ', time + delay - now, ' seconds\n');
      return;
    }

  if (! http_login_take_lock(port: port, now: now, delay: delay))
  {
    # Try to reload the cookie jar, in case another plugin updated it
    if (e != "") sleep(get_read_timeout());
    load_cookiejar(jar:"FormAuth");
    return;
  }

  page = get_kb_item("www/"+port+"/login_page");
  form = get_kb_item("www/"+port+"/login_form");
  fields = get_kb_item("www/"+port+"/login_fields");
  mt = get_kb_item("www/"+port+"/login_meth");

  e = http_form_login(port: port, page: page, form: form, fields: fields,
    save_cookies: save_cookies, method: mt, 
        check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic);
  if (e == "OK")
  {
    replace_kb_item( name: "www/"+port+"/"+SCRIPT_NAME+"/auth_OK", 
    		     value: ++ HttpLogin_reauthentication_OK);
    debug_print("Successful authentication on port ", port);
  }
  else if (e != "")
  {
    replace_kb_item( name: "www/"+port+"/"+SCRIPT_NAME+"/auth_KO", 
    		     value: ++ HttpLogin_reauthentication_KO);
    debug_print("Web authentication failed on port ", port, ": ", e);
  }
  replace_kb_item(name: "www/"+port+"/login_time", value: unixtime());

  http_login_release_lock(port);
}

