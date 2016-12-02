#TRUSTED 2e71bdba0f5a087225d60f0e54ab7545b91fc6996086f31c450dab671c20c044c56d8600a44d5d4d1fe0bd6ea165ace876a3ea572257bbbc52f7fb0bf5194416ce2e0a4a8f318ab31336de6f6d9ca5604fc334e80497284ef3cc263c01c68b142f2f28315275636e31dda85e5874417ef700fa8ee6667584efb05ac69d566e516f96d41ba99cdee3d4feafd09873143a5ec2b2d5b321668fb378ec7c3589b6de3335da1e462a5a704e07b3d40725374493ea744c8d7af0a06a422acccfa06b3257778995ebc8ee59be543d43c6e7fbd4c8340c889dc5740d98bec3c78115c11bd8869d0189b1e54bc9808b2265cd721f4eca33fb58ea40496f521d939b0f1857c3aaf115be77486c8624dc6acc36981036fb0548cc4e7e0d846a0efcfb88915757481695824bf215990b29568800a02bb85054001925978f129a16e122f1109ec10acb14d122614b32e68e66fef695709bbab6b9185daedbf7d2cfb96168c77f73c32dae21b3566fedcde35b0b9b86cfaecdcb6dced0f1cd3a2d2c5eae8a38d0e43b459d21d6b9efa27a485d0290c62c668fbf173e105e82b1a71ad89353c3206d6f0932b3072b02cbfc297076601f34f902efed5266bdf2e3831f71bfa0a124fe2abe2c6b1b68ca504d91c0f5c7d1ae0145f5b56593982013de6ebfb8f2ebf39d4d002f44f07ea9281246344f22bf6327089656f0290de8141897b669e50567
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
# smb_file.inc
# Revision: 1.24
#


#==================================================================#
# Section 8. File API                                              #
#==================================================================#


#---------------------------------------------------------#
# Function    : smb_file_resolve_path                     #
# Description : Remove . and .. from the passed in path   #
# Return      : NULL if path is invalid (to many ..)      #
#               the path without . and .. otherwise       #
# Note        : The return path will NEVER end in \       #
#---------------------------------------------------------#
function smb_file_resolve_path ()
{
  local_var path, part, stack_end, path_stack, rv;

  path = _FCT_ANON_ARGS[0];

  if (path == "")
    return path;

  if (typeof(path) !~ "(string|data)")
    return NULL;

  # Delete nonsense \\
  path = ereg_replace(pattern:"(\\\\)+", replace:"\", string:path);

  path = split(path, sep:"\", keep:FALSE);

  # Path was total non-sense
  if (max_index(path) == 0)
    return NULL;

  # Resolve the \.. within the path
  path_stack = make_list();
  stack_end  = max_index(path_stack);
  foreach part (path)
  {
    if (part == '.')
      continue;
    else if (part == '..')
      stack_end -= 1;
    else
      path_stack[stack_end++] = part;
    # Path backed up to far
    if (stack_end <= 0)
      return NULL;
  }

  # For path's ending in \.. stack_end must be decremented once more
  if (part == '..')
    stack_end -= 1;

  rv = "";
  # Path's without a drive letter start with \
  if (path_stack[0] !~ "^[A-Za-z]:$")
    rv += "\";

  for (part = 0; part <= stack_end; part++)
  {
    rv += path_stack[part];
    if (part != stack_end && rv !~ "\\$")
      rv += "\";
  }

  rv = ereg_replace(pattern:"\\+$", replace:"", string:rv);
  # Finally strip out \ from the end if it was left in
  return rv;
}

function get_win32_find_data_filename (struct)
{
 local_var len;

 if (strlen(struct) < 94)
   return NULL;

 len = get_dword (blob:struct, pos:60);
 if (strlen(struct) < 94 + len)
   return NULL;

 return get_string2 (blob:struct, pos:94, len:len);
}


function get_win32_find_data_fileattributes (struct)
{
 local_var len;

 if (strlen(struct) < 94)
   return NULL;

 return get_dword (blob:struct, pos:56);
}

function get_win32_find_data_filetimes (struct)
{
 local_var i, pos, ret;

 if (strlen(struct) < 94)
   return NULL;

 pos = 8;
 ret = make_list();
 for (i = 0; i < 4; i++)
 {
   ret[i] = convert_win64_time_to_unixtime(
     low  : get_dword (blob:struct, pos:pos),
     high : get_dword (blob:struct, pos:pos + 4)
   );

   pos += 8;
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : FindFirstFile                             #
# Description : Return First file in WIN32_FIND_DATA      #
# Return      : ret[0] = file handle                      #
#               ret[1] = file name                        #
#               ret[2] = file attributes                  #
#               ret[3] = file times                       #
#               full handle = ret (to use with NextFile)  #
#---------------------------------------------------------#

function direct_FindFirstFile (pattern)
{
 local_var ret, parameters, search_id, search_count, end_of_search, ea_error_offset, last_name_offset;
 local_var pad, data, index, pos, file_struct, size;

 if (session_is_smb2()) return FindFirstFile2(pattern:pattern);

 parameters = raw_word (w:0x16)   + # Default search : include HIDDEN/SYSTEM/DIRECTORY 
              raw_word (w:0xFFFF) + # Max buffer search count
              raw_word (w:6)      + # Close if EOS is reached / RESUME
              raw_word (w:260)    + # Default level of interest
              raw_dword (d:0)     + # Storage type
              cstring (string:pattern);

 ret = smb_trans2 (param:parameters, data:NULL, max_pcount:18, command:1); 
 if (!ret || (strlen (ret) < 14))
   return NULL;

 # FIND_FIRST2 Parameters
 search_id = get_word (blob:ret, pos:0);
 search_count = get_word (blob:ret, pos:2);
 end_of_search = get_word (blob:ret, pos:4);
 ea_error_offset = get_word (blob:ret, pos:6);
 last_name_offset = get_word (blob:ret, pos:8);

 # Padding
 pad = get_word (blob:ret, pos:10);

 # FIND_FIRST2 Data
 data = substr (ret, 12, strlen(ret)-1);

 # If no data we quit
 if (search_count <= 0)
   return NULL;
 
 index = 1;
 pos = 0;
 
 # FIND_FIRST2 Data
 size = get_word (blob:data, pos:pos);
 if (strlen (data) < size)
   return NULL;

 if (size == 0)
   size = strlen(data);
 
 file_struct = substr (data, pos, pos+size-1);

 pos += size;
 index++;

 ret = NULL;
 ret[0] = raw_word (w:search_id) +
          raw_word (w:search_count) +
          raw_word (w:end_of_search) +
          raw_word (w:index) +
          raw_dword (d:pos) +
          data;

 ret[1] = get_win32_find_data_filename (struct:file_struct);
 ret[2] = get_win32_find_data_fileattributes (struct:file_struct);
 ret[3] = get_win32_find_data_filetimes (struct:file_struct);

 return ret;
}



#---------------------------------------------------------#
# Function    : FindNextFile                              #
# Description : Return Next file in WIN32_FIND_DATA       #
# Return      : ret[0] = file handle                      #
#               ret[1] = file name                        #
#               ret[2] = file attributes                  #
#               ret[3] = file times                       #
#               full handle = ret                         #
#---------------------------------------------------------#

function direct_FindNextFile (handle)
{
 local_var ret, parameters, search_id, search_count, end_of_search, ea_error_offset, last_name_offset;
 local_var pad, data, index, pos, file_struct, size;

 if (session_is_smb2()) return FindNextFile2(handle:handle);

 if (strlen (handle[0]) < 13)
   return NULL;

 search_id = get_word (blob:handle[0], pos:0);
 search_count = get_word (blob:handle[0], pos:2);
 end_of_search = get_word (blob:handle[0], pos:4);
 index = get_word (blob:handle[0], pos:6);
 pos = get_dword (blob:handle[0], pos:8);
 data = substr (handle[0], 12, strlen (handle[0]) - 1);

 if (index > search_count)
 {
  if (end_of_search == 1)
    return NULL;

  parameters = raw_word (w:search_id) + # Search ID
               raw_word (w:0xFFFF)    + # Max search buffer size
               raw_word (w:260)       + # Default level of interest
               raw_dword (d:0)        + # storage type
               raw_word (w:6)         + # Close if EOS is reached / RESUME
               cstring (string:handle[1]);

  ret = smb_trans2 (param:parameters, data:NULL, max_pcount:8, command:2);
  if (!ret || (strlen (ret) < 10))
    return NULL;

  # FIND_FIRST2 Parameters
  search_count = get_word (blob:ret, pos:0);
  end_of_search = get_word (blob:ret, pos:2);
  ea_error_offset = get_word (blob:ret, pos:4);
  last_name_offset = get_word (blob:ret, pos:6);

  # FIND_FIRST2 Data
  data = substr (ret, 8, strlen(ret)-1);

  # If no data we quit
  if (search_count <= 0)
    return NULL;
 
  index = 1;
  pos = 0;
 } 
 
 size = get_word (blob:data, pos:pos);
 if (strlen (data) < size)
   return NULL;

 #last elem next offset param is null
 if (size == 0)
   size = strlen (data);
 
 file_struct = substr (data, pos, pos+size-1);
 pos += size;
 index++;

 ret = NULL;
 ret[0] = raw_word (w:search_id) +
          raw_word (w:search_count) +
          raw_word (w:end_of_search) +
          raw_word (w:index) +
          raw_dword (d:pos) +
          data;


 ret[1] = get_win32_find_data_filename (struct:file_struct);
 ret[2] = get_win32_find_data_fileattributes (struct:file_struct);
 ret[3] = get_win32_find_data_filetimes (struct:file_struct);

 return ret;
}


#---------------------------------------------------------#
# Function    : FindFirstFile2                            #
# Description : SMB2 version of FindFirstFile             #
#---------------------------------------------------------#

function FindFirstFile2(pattern)
{
 local_var fid, ret, qd, file, name;

 name = "";

 if (egrep(pattern:"(.*)\\[^\\]*$", string:pattern))
 {
  name = ereg_replace(pattern:"(.*)\\([^\\]*)$", string:pattern, replace:"\1");
  pattern = ereg_replace(pattern:"(.*)\\([^\\]*)$", string:pattern, replace:"\2");
 }

 ret = smb_create_and_x (name:name,
                         desired_access:FILE_GENERIC_READ,
                         flags_attributes:0,
                         share_mode:FILE_SHARE_READ,
                         create_disposition:OPEN_EXISTING,
                         create_options:0x20);
 if (isnull(ret))
   return ret;

 fid = ret[0];

 qd = smb2_query_directory(flags:0, index:0, pattern:pattern, id:fid);
 if (isnull(qd))
   return NULL;

 file = qd[0];

 ret = NULL;
 ret[0] = mklist(0, qd, fid, pattern);
 ret[1] = file[9];
 ret[2] = file[7];

 return ret;
}



#---------------------------------------------------------#
# Function    : FindNextFile2                             #
# Description : SMB2 version of FindNextFile              #
#---------------------------------------------------------#

function FindNextFile2(handle)
{
 local_var index, qd, ret, file, pattern, qd_pos, fid;

 if (isnull(handle)) return NULL;
 handle = handle[0];

 qd_pos = handle[0] + 1;
 qd = handle[1];
 fid = handle[2];
 pattern = handle[3];

 if (qd_pos >= max_index(qd))
 {
  file = qd[qd_pos-1];

  qd = smb2_query_directory(flags:SMB2_INDEX_SPECIFIED, index:file[0], pattern:pattern, id:fid);
  if (isnull(qd))
  {
   smb2_close(fid:fid);
   return NULL;
  }

  index++;
  qd_pos = 0;
 }

 
 file = qd[qd_pos];

 ret = NULL;
 ret[0] = mklist(qd_pos, qd, fid, pattern);
 ret[1] = file[9];
 ret[2] = file[7];

 return ret;
}


function win_props_to_mode (desired_access, file_attributes, share_mode, create_disposition)
{
  # only valid options are: "r", "w", "w+", "a", and "a+"

  if ( desired_access & (GENERIC_WRITE|FILE_APPEND_DATA) )
  {
	if ( desired_access & FILE_APPEND_DATA )
	{
	  if ( desired_access & GENERIC_READ )
		return "a+";
	  return "a";
	}
	else
	{
	  if ( create_disposition == CREATE_ALWAYS )
		return "w+";
	  return "w";
	}
  }
  else if ( desired_access & GENERIC_READ )
  {
	return "r";
  }

  return "";
}

#---------------------------------------------------------#
# Function    : CreateFile                                #
# Description : open a file                               #
#               return file handle                        #
#---------------------------------------------------------#

function direct_CreateFile (file, desired_access, file_attributes, share_mode, create_disposition, create_options)
{
 if (isnull(create_options)) create_options = 0;

 return smb_create_and_x (name:file,
                          desired_access:desired_access,
                          flags_attributes:file_attributes,
                          share_mode:share_mode,
                          create_disposition:create_disposition,
                          create_options:create_options);
}



#---------------------------------------------------------#
# Function    : ReadFile                                  #
# Description : Read data from file                       #
#---------------------------------------------------------#

function direct_ReadFile (handle, offset, length)
{
 local_var fid;

 fid = handle[0];

 return smb_read_and_x (fid:fid, offset:offset, length:length);
}



#---------------------------------------------------------#
# Function    : WriteFile                                 #
# Description : write data into file                      #
#---------------------------------------------------------#

function direct_WriteFile (handle, offset, mode, data)
{
 local_var fid;

 fid = handle[0];

 return smb_write_and_x (fid:fid, offset:offset, mode:mode, data:data);
}



#---------------------------------------------------------#
# Function    : CloseFile                                 #
# Description : close a file                              #
#---------------------------------------------------------#

function direct_CloseFile (handle)
{
 local_var fid;

 fid = handle[0];

 return smb_close (fid:fid);
}


#---------------------------------------------------------#
# Function    : DeleteFile                                #
# Description : delete a file                             #
#---------------------------------------------------------#

function direct_CloseAndDeleteFile (handle)
{
  local_var param, data;

  if (session_is_smb2())
  {
    # [MS-FSCC] section 2.4.11
    data = raw_byte(b:1); # DeletePending
    if (isnull(smb2_set_info(type:SMB2_0_INFO_FILE, class:FILE_DISPOSITION_INFORMATION,info:0, id:handle[0], data:data)))
      return NULL;
  }
  else
  {
    param = raw_word(w:handle[0]) + raw_word(w:1013) + raw_word(w:0);
    data = raw_byte(b:1);

    smb_trans2(param:param, data:data, max_pcount:10, command:0x08);
  }
  CloseFile(handle:handle);
}


#---------------------------------------------------------#
# Function    : GetSecurityInfo                           #
# Description : return security information               #
# Note        : only works with a file                    #
#---------------------------------------------------------#

function direct_GetSecurityInfo (handle, level)
{
 local_var parameters, ret, len;

 if (session_is_smb2())
 {
  ret = smb2_query_info(type:SMB2_0_INFO_SECURITY , class:0, info:level, id:handle[0]);
  if (isnull(ret))
    return ret;

  return parse_security_descriptor (blob:ret[3]);
 }
 else
 {
  parameters = raw_word (w:handle[0]) + # FID
               raw_word (w:0)         + # reserved
               raw_dword (d:level);

  ret = smb_nt_trans (param:parameters, data:NULL, command:0x06, max_pcount:4, max_dcount:0);
  if (strlen(ret) != 4)
    return NULL;

  len = get_dword (blob:ret, pos:0);
  ret = smb_nt_trans (param:parameters, data:NULL, command:0x06, max_pcount:4, max_dcount:len);

  if (strlen(ret) < 4)
    return NULL;

  len = get_dword (blob:ret, pos:0);
  if (strlen(ret) != 4 + len)
    return NULL;

  return parse_security_descriptor (blob:substr(ret, 4, strlen(ret)-1));
 }
}


#---------------------------------------------------------#
# Function    : GetFileSize                               #
# Description : return file size                          #
#---------------------------------------------------------#

function direct_GetFileSize (handle)
{
 local_var size;

 size = handle[1];

 # size = low DWORD + high DWORD
 # we just don't care about high DWORD for the moment
 return get_dword (blob:size, pos:0);
}


function voffset_to_offset (voffset, sections)
{
 local_var num, i, section;

 num = max_index (sections);
 for (i=0; i<num; i++)
 {
  section = sections[i];

  if ((voffset >= section[3]) && (voffset <= (section[3] + section[1])))
    return section[2] + (voffset - section[3]);
 }

 # should not reach this code
 return 0;
}

function _get_version(offset, sections, handle)
{
 local_var info_offset, version_info, len, pos, ret, sig, res_dir;

 # VERSION : offset + size
 res_dir = ReadFile (handle:handle, offset:offset, length:8);
 if (!res_dir || strlen(res_dir) != 8)
   return NULL;
 
 info_offset = get_dword (blob:res_dir, pos:0);

 # Convert Vitual address to offset
 offset = voffset_to_offset (voffset:info_offset, sections:sections);
 
 # VS_VERSION_INFO
 version_info = ReadFile (handle:handle, offset:offset, length:2);
 if (!version_info || strlen(version_info) != 2)
   return NULL;

 len = get_word (blob:version_info, pos:0);
 if (len < 58)
   return NULL;

 # VS_VERSION_INFO
 version_info = ReadFile (handle:handle, offset:offset, length:len);
 if (!version_info || strlen(version_info) != len)
   return NULL;

 ret = NULL;
 ret['wLength']            = get_word (blob:version_info, pos:0);
 ret['wValueLength']       = get_word (blob:version_info, pos:2);
 ret['wType']              = get_word (blob:version_info, pos:4);
 ret['szKey']              = get_string (blob:version_info, pos:6, _type:1);

 pos = 6 + strlen (ret['szKey']) * 2 + 2;

 # word of padding padding
 if (strlen(ret['szKey']) % 2)
 {
  ret['Padding1'] = 0;
  pos += 2;
 }

 sig = get_dword (blob:version_info, pos:pos);
 if (sig != 0xfeef04bd)
   return NULL;

 ret['dwSignature']         = get_dword (blob:version_info, pos:pos);
 ret['dwStrucVersion']      = get_dword (blob:version_info, pos:pos+4);
 ret['dwFileVersionMS']     = get_dword (blob:version_info, pos:pos+8);
 ret['dwFileVersionLS']     = get_dword (blob:version_info, pos:pos+12);
 ret['dwProductVersionMS']  = get_dword (blob:version_info, pos:pos+16);
 ret['dwProductVersionLS']  = get_dword (blob:version_info, pos:pos+20);
 ret['dwFileFlagsMask']     = get_dword (blob:version_info, pos:pos+24);
 ret['dwFileFlags']         = get_dword (blob:version_info, pos:pos+28);
 ret['dwFileOS']            = get_dword (blob:version_info, pos:pos+32);
 ret['dwFileType']          = get_dword (blob:version_info, pos:pos+36);
 ret['dwFileSubtype']       = get_dword (blob:version_info, pos:pos+40);
 ret['dwFileDateMS']        = get_dword (blob:version_info, pos:pos+44);
 ret['dwFileDateLS']        = get_dword (blob:version_info, pos:pos+48);

 if ( NASL_LEVEL < 2204 )
   return ret;

 pos += 52;

 ret['Children'] = extract_structures (data:substr(version_info, pos, strlen(version_info)-1));

 return ret;
}

function check_version (size, offset, sections, handle)
{
 local_var i, sig, ret, id, info_offset, res_dir, NumberOfNamedEntries, NumberOfIdEntries, entry, version_info, len, pos, num, res_dir_entry, section_found, code, ver_offset, ver;

 # IMAGE_RESOURCE_DIRECTORY structure
 res_dir = ReadFile (handle:handle, offset:offset, length:16);
 if (!res_dir || strlen(res_dir) != 16)
   return NULL;
 
 NumberOfNamedEntries = get_word (blob:res_dir, pos:12);
 NumberOfIdEntries = get_word (blob:res_dir, pos:14);

 info_offset = 0;

 for (i = 0; i < NumberOfNamedEntries + NumberOfIdEntries; i++)
 {
  entry = ReadFile (handle:handle, offset:offset+16+i*8, length:8);
  if (!entry || strlen(entry) != 8)
    return NULL;
 
  id = get_dword (blob:entry, pos:0);
  if (id == 0x10) # VERSION_INFO structure
  {
   info_offset = get_dword (blob:entry, pos:4) - 0x80000000;
   break;
  }
 }

 if (info_offset == 0)
   return NULL;

 # VERSION : IMAGE_RESOURCE_DIRECTORY 1
 res_dir = ReadFile (handle:handle, offset:offset+info_offset, length:24);
 if (!res_dir || strlen(res_dir) != 24)
   return NULL;
 
 info_offset = get_dword (blob:res_dir, pos:20) - 0x80000000;


 # VERSION : IMAGE_RESOURCE_DIRECTORY 2
 res_dir = ReadFile (handle:handle, offset:offset+info_offset, length:16);
 if (!res_dir || strlen(res_dir) != 16)
   return NULL;
 
 num = get_word(blob:res_dir, pos:14);
 section_found = FALSE;
 ret = NULL;

 # version info is stored per locale. loop through each locale, using the en-US version info if possible.
 # if it's not available, extract the last non-null version info that was seen
 for (i=0; i<num; i++)
 {
  res_dir_entry = ReadFile (handle:handle, offset:offset+info_offset+16+i*8, length:8);
  if (!res_dir || strlen(res_dir_entry) != 8)
    return NULL;
 
  code = get_dword(blob:res_dir_entry, pos:0);
  ver_offset = get_dword (blob:res_dir_entry, pos:4);
  ver = _get_version(offset:offset + ver_offset, sections:sections, handle:handle);

  if (isnull(ver))
    continue;
  else
    ret = ver;

  if (code == 0x409) # 0x409 = 1033 = en-US
    break;
 }

 return ret;
}

function extract_structures (data)
{
 local_var opos, pos, len, size, type, max_len, ret, name;

 ret = NULL;

 pos = 0;
 max_len = strlen(data);

 while (pos < max_len)
 {
  opos    = pos;
  len     = get_word (blob:data, pos:pos);
  size    = get_word (blob:data, pos:pos+2);
  type    = get_word (blob:data, pos:pos+4);

  name = get_string (blob:data, pos:pos+6, _type:1);
  pos = pos+6 + strlen (name) * 2 + 2;
  
  # word of padding
  if (strlen(name) % 2)
    pos += 2;

  if (size == 0)
    ret[name] = extract_structures (data:substr(data,pos,opos+len-1));
  else
  {
   # WCHAR
   if (type == 1)
     ret[name] = get_string (blob:data, pos:pos, _type:1);
   # Binary data
   else
     ret[name] = substr (data, pos, pos+size-1);
  }

  pos = opos + len;
  if (len % 4)
    pos += 2;
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : GetFileVersionEx                          #
# Description : return file version (exe,dll,...)         #
# Return      : VS_VERSION_INFO structure :               #
#                                                         #
# VS_VERSION_INFO :                                       #
#    ret['dwTimeDateStamp'];                              #
#    ret['wLength'];                                      #
#    ret['wValueLength];                                  #
#    ret['wType'];                                        #
#    ret['szKey'];                                        #
#    [ret['Padding1']];                                   #
#    #VS_FIXEDFILEINFO Value;                             #
#     ret['dwSignature'];                                 #
#     ret['dwStrucVersion'];                              #
#     ret['dwFileVersionMS'];                             #
#     ret['dwFileVersionLS'];                             #
#     ret['dwProductVersionMS'];                          #
#     ret['dwProductVersionLS'];                          #
#     ret['dwFileFlagMask'];                              #
#     ret['dwFileFlags'];                                 #
#     ret['dwFileOS'];                                    #
#     ret['dwFileType'];                                  #
#     ret['dwFileSubtype'];                               #
#     ret['dwFileDateMS'];                                #
#     ret['dwFileDateLS'];                                #
#    ret['Children'];                                     #
#       --> ['StringFileInfo']                            #
#          --> ['040904B0']                               #
#             --> ['CompanyName'] = "Tenable Network Sec."#
#             --> ['FileVersion'] = "6.0.45.366"          #
#             --> ...                                     #
#       --> ['VarFileInfo']                               #
#          --> ['Translation'] = raw_string ("0904B004")  #
#                                                         #  
#                                                         #
#---------------------------------------------------------#

function direct_GetFileVersionEx (handle)
{
 local_var dos_header, sig, e_lfanew, nt_header, number_of_sections, size_optional_header, i;
 local_var offset, size, sections, pos, idx, tmp, pattern, rsrc, r_pattern, ret, name, voffset;
 local_var __sections, section, time_date_stamp;

 # We first parse IMAGE_DOS_HEADER
 dos_header = ReadFile (handle:handle, offset:0, length:64);
 if (!dos_header || (strlen(dos_header) != 64))
   return NULL;

 sig = substr(dos_header, 0, 1);
 if ("MZ" >!< sig)
   return NULL;

 e_lfanew = get_dword (blob:dos_header, pos:60);


 # We now parse Signature + IMAGE_FILE_HEADER
 nt_header = ReadFile (handle:handle, offset:e_lfanew, length:24);
 if (!nt_header || (strlen(nt_header) != 24))
   return NULL;

 sig = substr(nt_header, 0, 1);
 if ("PE" >!< sig)
   return NULL;

 number_of_sections = get_word (blob:nt_header, pos:6);
 time_date_stamp = get_dword (blob:nt_header, pos:8);
 size_optional_header = get_word (blob:nt_header, pos:20);

 
 # We now parse sections
 offset = e_lfanew + 24 + size_optional_header;
 size = number_of_sections * 40;
 sections = ReadFile (handle:handle, offset:offset, length:size);
 if (!sections || (strlen(sections) != size))
   return NULL;

 pos = rsrc = 0;
 r_pattern = ".rsrc" + raw_string(0);

 __sections = NULL;
 for (i=0; i<number_of_sections; i++)
 {
  section = make_list (
	substr(sections, pos, pos+7),                     # name
  	get_dword (blob:sections, pos:pos+16),            # size
  	get_dword (blob:sections, pos:pos+20),            # offset
  	get_dword (blob:sections, pos:pos+12)             # voffset
	);

  if (r_pattern >< section[0])
  {
   rsrc = 1;
   offset = section[2];
   size = section[1];
  }

  __sections[i] = section;

  pos += 40;
 }

 # if no rsrc section left
 if (rsrc == 0)
   return NULL; 

 ret = check_version (size:size, offset:offset, sections:__sections, handle:handle);

 ret['dwTimeDateStamp'] = time_date_stamp;

 return ret;
}

#---------------------------------------------------------#
# Function    : GetFileVersion                            #
# Description : return file version (exe,dll,...)         #
# Return      : ret[0] = version 0                        #
#               ret[1] = version 1                        #
#               ret[2] = version 2                        #
#               ret[3] = version 3                        #
#---------------------------------------------------------#

function GetFileVersion (handle)
{
 local_var ret, tmp;

 ret = GetFileVersionEx (handle:handle);
 if (isnull(ret) || isnull(ret['dwFileVersionMS']) || isnull(ret['dwFileVersionLS']))
   return NULL;

 tmp = NULL;
 tmp[0] = ret['dwFileVersionMS'] >>> 16;
 tmp[1] = ret['dwFileVersionMS'] & 0xFFFF;
 tmp[2] = ret['dwFileVersionLS'] >>> 16;
 tmp[3] = ret['dwFileVersionLS'] & 0xFFFF;

 return tmp;
}


#----------------------------------------------------------#
# Function    : convert_dword                              #
# Description : returns the string version of a dword,     #
#               with endianness corrected. helper function #
#               for GetProductVersion().                   #
# Args        : dword - dword to convert                   #
#               nox - TRUE if a leading '0x' should _not_  #
#                     be prepended (default is FALSE)      #
# Return      : The converted dword                        #
#----------------------------------------------------------#
function convert_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}

#----------------------------------------------------------#
# Function    : GetProductVersion                          #
# Description : Extracts the ProductVersion from a file    #
# Args        : Filehandle of the file to get version from #
# Return      : The ProductVersion if it was extracted,    #
#               NULL otherwise                             #
#----------------------------------------------------------#
function GetProductVersion(handle)
{
 local_var ret, children, varfileinfo, translation, stringfileinfo, data;
 local_var key,prod_ver;
 prod_ver = NULL;

 if (!isnull(handle)) ret = GetFileVersionEx(handle:handle);
 if (!isnull(ret)) children = ret['Children'];

 if (!isnull(children))
 {
   varfileinfo = children['VarFileInfo'];
   if (!isnull(varfileinfo))
   {
     translation =
       (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
       get_word (blob:varfileinfo['Translation'], pos:2);
     translation = tolower(convert_dword(dword:translation, nox:TRUE));
   }
   stringfileinfo = children['StringFileInfo'];
   if (!isnull(stringfileinfo) && !isnull(translation))
   {
     # case of 'translation' can differ from file to file
     data = stringfileinfo[translation];
     if (isnull(data)) data = stringfileinfo[toupper(translation)];

     # Fall back to using the sole key if there's only one and 
     # the translation didn't work.
     if (isnull(data) && max_index(keys(stringfileinfo)) == 1)
     {
       foreach key (keys(stringfileinfo))
       {
         data = stringfileinfo[key];
         break;
       }
     }
     if (!isnull(data)) prod_ver = data['ProductVersion'];
   }
 }

 return prod_ver;
}

#----------------------------------------------------------#
# Function    : GetProductName                             #
# Description : Extracts the ProductName from a file       #
# Args        : Filehandle of the file to get version from #
# Return      : The ProductName if it was extracted,       #
#               NULL otherwise                             #
#----------------------------------------------------------#
function GetProductName(handle)
{
  local_var ret, children, varfileinfo, translation, stringfileinfo, data;
  local_var key,prod_name;
  prod_name = NULL;

  if (!isnull(handle)) ret = GetFileVersionEx(handle:handle);
  if (!isnull(ret)) children = ret['Children'];

  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
        (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word (blob:varfileinfo['Translation'], pos:2);
      translation = tolower(convert_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      # case of 'translation' can differ from file to file
      data = stringfileinfo[translation];
      if (isnull(data)) data = stringfileinfo[toupper(translation)];

      # Fall back to using the sole key if there's only one and
      # the translation didn't work.
      if (isnull(data) && max_index(keys(stringfileinfo)) == 1)
      {
        foreach key (keys(stringfileinfo))
        {
          data = stringfileinfo[key];
          break;
        }
      }
      if (!isnull(data)) prod_name = data['ProductName'];
    }
  }

  return prod_name;
}

##
# Wrapper around [CreateFile] that permits wildcards.
#
# This function accepts '*' wildcards in the file parameter in the
# place of a directory. Wildcards are replaced with the results from
# [FindFirstFile] and [FindNextFile], recursively, until a match is
# found for the entire path, or until it runs out of options.
#
# @param create_disposition See [CreateFile].
# @param desired_access See [CreateFile].
# @param file Path to file, which may include wildcards.
# @param file_attributes See [CreateFile].
# @param share_mode See [CreateFile].
#
# @remark Each wildcard will match a single directory and nothing else.
#
# @return A valid file handle or null if no matching path was found.
##
function FindFile(create_disposition, desired_access, file, file_attributes, share_mode)
{
  local_var dh, fh, head, part, subpaths, tail;

  # If there aren't any wildcards, then we just pass it off to CreateFile.
  subpaths = split(file, sep:"\*");
  if (max_index(subpaths) == 1)
  {
    return CreateFile(
      file               : file,
      desired_access     : desired_access,
      file_attributes    : file_attributes,
      share_mode         : share_mode,
      create_disposition : create_disposition
    );
  }

  # Put the path mostly back together.
  head = ereg_replace(string:subpaths[0], pattern:"[*]", replace:"");
  tail = make_list();
  foreach part (subpaths)
  {
    if (part == subpaths[0]) continue;
    tail = make_list(tail, part);
  }
  tail = join(tail, sep:"");

  # Walk the head directory.
  for (
    dh = FindFirstFile(pattern:head + "*");
    !isnull(dh) && isnull(fh);
    dh = FindNextFile(handle:dh)
  )
  {
    # Skip non-directories.
    if (dh[2] & FILE_ATTRIBUTE_DIRECTORY == 0) continue;

    # Skip current and parent directories.
    if (dh[1] == "." || dh[1] == "..") continue;

    # Recurse.
    fh = FindFile(
      file               : head + dh[1] + tail,
      desired_access     : desired_access,
      file_attributes    : file_attributes,
      share_mode         : share_mode,
      create_disposition : create_disposition
    );
  }

  return fh;
}
