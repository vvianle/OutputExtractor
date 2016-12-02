#TRUSTED 907cc71b2f6d1fe427b6c28b27ae0b7d0d42c3e329fc05feb24be68b129cda8bc4f9fad5585834982f490af235afd1fa9e30d70fdb0c463d55991ace8a384565c807aa9d8d25ef0213a090b956b96f26b26bba5fde42e7d80431ad394d7b7c44c0c98f11cd62d37f6649098f5e13855483bbb34ef4bd19ff61856be98ad3b170da97fbc94900cb945b400445521adc0368f5f0f47a68194fba3ec5ca906e9b9cb9446ad26bda16362a9d681378ae9393e5907eb38087ed640ef6adb430e195652a0b45b4035912293d1041bd88e0e649a713f126268fd610aeb977ba9bf5678e7fc4136cced09d356a03463237bafe6c9ddfcf352359cfb5a43270ffe9922a5dc31e629728d2d5e19249de2743b1ab56fe7bf982f9f1b5bd83c69ae49a8d7c133229d51958c11c19359afa15ba3667160ba3acf8b4d0a30dfecde0554e3ce21e24f59c9b3b1bc614277e67d295078ea6ff8de39fd1d731dce2f17eeecb6f010e3a86522db6427bce2db3c98891c10f2ec3a9f0d79dcdf5a79a0c1b5d179c37959c76d6e7e514eb09659bae94db71edd4254647bc63002d99cef2ebc2da39c546114de003d7e0a9f6a2073a40540f347aa352575cec8158810d336b34575ef2c0f30ffc4350108487187acaae5a032fed122b44778e470a498867bd1b4d65da1e69441370e7b27f9dcaa8348178d0fbe9add0786db0d6173c38ce9f1e38c978e4
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# obj.inc
#
# Revision 1.5
#

######################################################################
# Private Comparison Functions
######################################################################

##
# Compares two NASL arrays.
#
# @anonparam a First array to be compared
# @anonparam b Second array to be compared
#
# @return TRUE if both arrays contain the same data
##
function _obj_cmp_array()
{
  local_var a, b, key_a, key_b, keys_a, keys_b;

  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  # Get the list of keys for both arrays.
  keys_a = keys(a);
  keys_b = keys(b);

  # Ensure both arrays have the same number of keys. This prevents us
  # from having to worry about keys in array b that don't exist in
  # array a.
  if (max_index(keys_a) != max_index(keys_b))
    return FALSE;

  # Compare the pairs in both arrays.
  foreach key_a (keys_a)
  {
    # Since you can store NULLs in an array and keys() will return the
    # keys they're stored at, we can't just index the array and check
    # for NULL to determine whether the key exists.
    foreach key_b (keys_b)
    {
      # Ensure array b has this key. When a NASL object is used as a
      # key, it is cast to an object of type "data". This means that
      # we can compare keys directly.
      if (key_a == key_b)
        break;
    }

    # If these keys aren't the same, array a contains a key that
    # array b doesn't.
    if (key_a != key_b)
      return FALSE;

    # Compare the values of the keys.
    if (!_obj_cmp(a[key_a], b[key_b]))
      return FALSE;
  }

  return TRUE;
}

##
# Compares two NASL objects.
#
# @anonparam a First object to be compared
# @anonparam b Second object to be compared
#
# @return TRUE if both objects contain the same data
##
function _obj_cmp()
{
  local_var a, b, type_a, type_b;

  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  # Both objects must be of the same type.
  type_a = typeof(a);
  type_b = typeof(b);
  if (type_a != type_b)
    return FALSE;

  # This type represents both integers and the constants TRUE and
  # FALSE.
  if (type_a == "int")
    return (a == b);

  # This type represents unsigned integers.
  if (type_a == "uint")
    return (a == b);

  # This type represents double-quoted strings.
  if (type_a == "string")
    return (a == b);

  # This type represents single-quoted strings.
  if (type_a == "data")
    return (a == b);

  # This type represents both the constant NULL and undefined
  # variables.
  if (type_a == "undef")
    return TRUE;

  # This type represents both arrays and lists, since the latter is
  # implemented as the former.
  if (type_a == "array")
    return _obj_cmp_array(a, b);

  # Unsupported data type.
  return FALSE;
}

######################################################################
# Private Random Functions
######################################################################

##
# Generates a random NASL string object.
#
# @param max_chars The maximum number of characters in the string
#                  object
#
# @remark The generated string object will contain only printable
#         ASCII.
#
# @return A randomly generated string object.
##
function _obj_random_string(max_chars)
{
  local_var ascii, i, len, s;

  # Randomly determine the number of bytes to generate.
  len = rand() % max_chars;

  # We cannot generate strings from numbers, since the only builtin
  # functions for that produce data, not string, objects. This
  # limitation forces the use of a literal list.
  #
  # Additionally, the below list is missing the double-quote
  # character, since there is *no* way to add this to a string object
  # without it becoming a data object.
  ascii = make_list(
    "!", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".",
    "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";",
    "<", "=", ">", "?", "@", "A", "B", "C", "D", "E", "F", "G", "H",
    "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U",
    "V", "W", "X", "Y", "Z", "[", "\", "]", "^", "_", "`", "a", "b",
    "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
    "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "{", "|",
    "}", "~"
  );

  s = "";
  for (i = 0; i < max_chars; i++)
    s += ascii[rand() % max_index(ascii)];

  return s;
}

##
# Generates a random NASL data object.
#
# @param max_chars The maximum number of characters in the data object
#
# @remark The generated data object may contain any 8-bit value.
#
# @return A randomly generated data object.
##
function _obj_random_data(max_chars)
{
  local_var i, len, s;

  # Randomly determine the number of bytes to generate.
  len = rand() % max_chars;

  s = "";
  for (i = 0; i < len; i++)
    s += raw_string((rand() % 255) + 1);

  return s;
}

##
# Generates a random NASL array object.
#
# @param int_keys  Determines whether generated keys must be integers
# @param max_chars The maximum number of characters in any string
# @param max_depth The maximum depth of the data structure
# @param max_keys  The maximum number of keys at any level of the
#                  data structure
#
# @return A randomly generated array object.
##
function _obj_random_array(int_keys, max_chars, max_depth, max_keys)
{
  local_var ds, i, len, key, val;

  # Randomly determine the number of keys to generate.
  len = rand() % max_keys;

  # Initialize the data structure.
  if (int_keys)
    ds = make_list();
  else
    ds = make_array();

  # Populate the data structure.
  for (i = 0; i < len; i++)
  {
    # Keys are data objects for arrays, and integer objects (that are
    # cast to data objects) for lists. Note that there is a chance of
    # a random key being generated twice, especially with low values
    # of max_chars.
    if (int_keys)
      key = i;
    else
      key = _obj_random_data(max_chars:max_chars);

    # Values in arrays and lists can be anything.
    val = obj_random(
      max_chars : max_chars,
      max_depth : max_depth - 1,
      max_keys  : max_keys
    );

    ds[key] = val;
  }

  return ds;
}

######################################################################
# Public Functions
######################################################################

##
# Compares any number of NASL objects.
#
# @anonparam obj1 First object to be compared
# @anonparam obj2 Second object to be compared
# @anonparam objN Nth object to be compared
#
# @return True if all objects contain the same data
##
function obj_cmp()
{
  local_var i, len;

  # Get the number of objects passed.
  len = max_index(_FCT_ANON_ARGS);

  # Compare the first object to all other objects.
  for (i = 1; i < len; i++)
  {
    if (!_obj_cmp(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[i]))
      return FALSE;
  }

  return TRUE;
}

##
# Produces a random NASL data structure.
#
# @param max_chars The maximum number of characters in any string
# @param max_depth The maximum depth of the data structure
# @param max_keys  The maximum number of keys at any level of the
#                  data structure
#
# @return A NASL random generated data structure
##
function obj_random(max_chars, max_depth, max_keys)
{
  local_var type, types;

  # Pick a random maximum number of characters if none was specified,
  # or an invalid value was given.
  if (isnull(max_chars) || max_chars < 0)
    max_chars = (rand() % 256);

  # Pick a random maximum depth if none was specified, or an invalid
  # value was given.
  if (isnull(max_depth) || max_depth <= 0)
    max_depth = (rand() % 10) + 1;

  # Pick a random maximum number of keys if none was specified, or an
  # invalid value was given.
  if (isnull(max_keys) || max_keys <= 0)
    max_keys = (rand() % 10) + 1;

  # Pick a random data type for this level of the structure. This has
  # a 2/3 chance of each level being the last.
  types = make_list("data", "int", "string", "uint", "undef");
  if (max_depth > 2)
    types = make_list(types, "array", "list");
  type = types[rand() % max_index(types)];

  if (type == "int")
    return rand();

  if (type == "uint")
    return uint(rand());

  if (type == "string")
    return _obj_random_string(max_chars:max_chars);

  if (type == "data")
    return _obj_random_data(max_chars:max_chars);

  if (type == "undef")
    return NULL;

  if (type == "list")
    return _obj_random_array(
      max_chars : max_chars,
      max_depth : max_depth - 1,
      max_keys  : max_keys,
      int_keys  : TRUE
    );

  if (type == "array")
    return _obj_random_array(
      max_chars : max_chars,
      max_depth : max_depth - 1,
      max_keys  : max_keys,
      int_keys  : FALSE
    );
}

##
# Convert data structure into a string of NASL code.
#
# @anonparam ds Data structure to be converted
#
# @param indent String to be used for as indentation
# @param depth  Depth of recursion
#
# @return String representing the data structure.
##
function obj_rep(depth, indent)
{
  local_var ch, ds, escs, i, idxs, key, len, max, n, prefix, str, type, val;

  if (isnull(depth))
    depth = 1;

  if (isnull(indent))
    indent = "  ";

  len = strlen(indent);

  ds = _FCT_ANON_ARGS[0];
  type = typeof(ds);

  # This type represents both integers and the constants TRUE and
  # FALSE.
  if (type == "int")
    return ds;

  # This type represents unsigned integers.
  if (type == "uint")
    return 'uint(' + string(uint(ds)) + ')';

  # This type represents double-quoted strings.
  if (type == "string")
    return '"' + ds + '"';

  # This type represents single-quoted strings.
  if (type == "data")
  {
    escs = make_array(
      '\0', '\\0',
      '\'', '\\\'',
      '\\', '\\\\',
      '\n', '\\n',
      '\r', '\\r',
      '\t', '\\t'
    );

    val = "";
    max = strlen(ds);

    for (i = 0; i < max; i++)
    {
      key = ds[i];
      ch = escs[key];

      if (isnull(ch))
      {
        n = ord(key);
        if (n < 0x20 || n > 0x7E)
        {
          ch = toupper(hex(n));
          ch[0] = "\";
          ch[1] = "x";
        }
        else
        {
          ch = key;
        }
      }

      val += ch;
    }

    return "'" + val + "'";
  }

  # This type represents both the constant NULL and undefined
  # variables.
  if (type == "undef")
    return "NULL";

  # This type represents both arrays and lists, since the latter is
  # implemented as the former.
  if (type == "array")
  {
    if (is_list(ds))
      type = "list";

    str = "";
    prefix = crap(data:indent, length:depth * len);

    # Create the representation of the object.
    str += "make_nested_" + type + "(";

    # Extract the keys and see how many we're dealing with.
    if (type == "array")
    {
      idxs = numsort(keys(ds));
      max = max_index(idxs);
    }
    else
    {
      max = max_index(ds);
    }

    # Use compressed representation if the object is empty.
    if (max == 0)
      return str + ")";

    # Create the representation of the object's contents.
    for (i = 0; i < max; i++)
    {
      # Finish off the previous line appropriately.
      if (i > 0)
        str += ",";
      str += '\n' + prefix;

      # Extract the key-value pair.
      if (type == "array")
        key = idxs[i];
      else
        key = i;
      val = ds[key];

      # Add in the key for arrays.
      if (type == "array")
        str += obj_rep(key, depth:depth + 1, indent:indent) + ", ";

      # Add the value for both lists and arrays.
      str += obj_rep(val, depth:depth + 1, indent:indent);
    }

    # Close the representation of the object.
    str += '\n' + crap(data:indent, length:(depth - 1) * len) + ")";

    return str;
  }

  # Unsupported data type.
  return "<unknown>";
}

##
# Returns true if provided value is found in provided list.
#
# @remark Supports all data types supported by obj_cmp.
#
# @param list The list to search through.
# @param item The item to look for.
#
# @return TRUE if an item exists in list, FALSE otherwise.
##
function obj_in_list(list, item)
{
  local_var candidate;

  foreach candidate (list)
  {
    if (obj_cmp(candidate, item))
      return TRUE;
  }

  return FALSE;
}
