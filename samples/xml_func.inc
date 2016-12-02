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
# xml_func.inc
# $Revision: 1.2 $
#
##
# The purpose of this file is to make it easier to parse and analyze large
# XML structures. Note that these functions operate on tables, not directly
# on XML - the tables are the ones created by xmlparse(). 
##

###
# A mapping between characters used in syntax and their entity names.
# e.g. & corresponds to "amp".
#
# The purpose of this list is to allow translation such as converting <
# to &lt; though the "&" and ";" are not included in the table entries.
###
global_var XML_SYNTAX_CHAR_TABLE;
XML_SYNTAX_CHAR_TABLE = make_array(
  '"', "quot",
  '&', "amp",
  "'", "apos",
  '<', "lt",
  '>', "gt"
);

##
# Retrieve the first child in the node with the given name. For example,
# in the following XML structure:
#
# <authors>
#   <author>Ron</author>
#   <author>John</author>
# </author>
#
# Calling this for the name 'author' would return a table representing the
# first author ("Ron"). 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @param name  The name to retrieve.
#
# @return An XML tables representing the node, or NULL if none were found.
##
function xml_get_child(table, name)
{
  local_var child;

  if(isnull(name))
    exit(1, "Invalid 'name' value passed to xml_get_child");

  foreach child(table['children'])
  {
    if(child['name'] == name)
      return child;
  }

  return NULL;
}

##
# Retrieve all children in the node with the given name. For example,
# in the following XML structure:
#
# <authors>
#   <author>Ron</author>
#   <author>John</author>
# </author>
#
# Calling this for the name 'author' will return an array containing two
# elements - the node for 'Ron' and the node for 'John'. 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @param name  The name to retrieve.
#
# @return An array of XML tables representing the nodes, or NULL if none were
#         found. 
##
function xml_get_children(table, name)
{
  local_var child, result;

  if(isnull(name))
    exit(1, "Invalid 'name' value passed to xml_get_child");

  result = make_list();
  foreach child(table['children'])
  {
    if(child['name'] == name)
      result[max_index(result)] = child;
  }

  return result;
}

## 
# Get a list of names of all sub-nodes. For example, in the following XML
# structure:
#
# <author>
#   <name>Ron</name>
#   <country>Canada</country>
# </author>
#
# Calling this would return a list containing 'name' and 'country'. 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @return An array of names, or an empty array if this node was empty.
##
function xml_get_children_names(table)
{
  local_var child, result;

  result = make_list();
  foreach child(table['children'])
    result = make_list(result, child['name']);

  return result;
}

## 
# Get a list of name/value pairs of all sub-nodes. For example, in the
# following XML structure:
#
# <author>
#   <name>Ron</name>
#   <country>Canada</country>
# </author>
#
# Calling this would return a list containing 'name'=>'Ron' and
# 'country'=>'Canada'.
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @return An array of names/values, or an empty array if this node was empty.
##
function xml_get_names_values(table)
{
  local_var child, result;

  result = make_array();
  foreach child(table['children'])
    result[child['name']] = child['value'];

  return result;
}

##
# Attempt to turn the XML table back into an XML string. This isn't 100%
# effective - for example, it doesn't properly encode symbols - so at the
# moment it's best to use this for debugging purposes only.
#
# @param table   An XML table, returned by xmlparse() or any of the various
#                xml_get_* functions. 
# @param _indent An internal variable used for recursion.
# @return A string representing the XML data. 
##
function _xml_table_to_string(table, _indent)
{
  local_var _indent_str, result, attribute, child;

  if(isnull(_indent))
    _indent = 0;
  _indent_str = crap(data:' ', length:_indent * 2);

  # Do the opening tag
  result = _indent_str + "<" + table['name'];
  foreach attribute(keys(table['attributes']))
    result = result + (' ' + attribute + '="' + table['attributes'][attribute] + '"');  

  # If the string is all space/newline, it's basically blank
  if(ereg(string:table['value'], pattern:'^[ \n]*$', multiline:TRUE))
    table['value'] = NULL;

  # Handle a 'value' field
  if(!isnull(table['value']) && table['value'] != '')
  {
    result = result + '>' + table['value'] + "</" + table['name'] + '>\n';
  }
  # Handle the case where there are no children
  else if(max_index(table['children']) == 0)
  {
    result = result + '\\>\n';
  }
  # Handle the case where there are children
  else
  {
    result = result + '>\n';

    foreach child(table['children'])
    {
      result = result + xml_table_to_string(table:child, _indent:_indent + 1);
    }
    result = result + _indent_str + "</" + xml['name'] + '>\n';
  }

  return result;
}

##
# Replace syntactical characters with XML entities such that it is safe
# to use the given string in attribute values and content.
#
# @anonparam str The string to replace the characters in.
#
# @remark Non-idempotent; this function will re-escape already escaped strings.
#
# @return a string suitable for an attribute value or textual content.
##
function xml_escape()
{
  local_var char, replacement, str;

  str = _FCT_ANON_ARGS[0];

  # Substitute "&" first so we don't escape any we add.
  foreach char (list_uniq(make_list("&", keys(XML_SYNTAX_CHAR_TABLE))))
  {
    replacement = "&" + XML_SYNTAX_CHAR_TABLE[char] + ";";
    str = str_replace(string:str, find:char, replace:replacement);
  }

  return str;
}
