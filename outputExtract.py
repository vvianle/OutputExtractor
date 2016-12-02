
from os.path import basename

class OutputExtract(object):

  def __init__(self, inputLink):
    self.inputLink = inputLink
    inFile = open(inputLink)
    outFile = open("output/"+basename(inputLink)+"-output.txt", "w")
    self.search(inFile, outFile)
    inFile.close()
    outFile.close()
    

  def search(self, inFile, outFile):

    search = True

    for line in inFile:

      if search:
        if line.startswith("if(description)") or line.startswith("if (description)"):
          search = False
        	
        elif re.compile("^\s*(else|if|#\s).*[^;]\n$").match(line):
          pass

        else:
          for value in re.findall('"(.*?)"', line):
          			
          	if re.compile(".*?'\s\+.*?'.*?").match(value):
          		pass
          			
          	elif line.startswith("include"):
          		smallFile = open("samples/"+value)
          		self.search(smallFile, outFile)
          		smallFile.close()
          	else:
          		outFile.write(value+"\n")

          for value in re.findall("(.?'.*?')", line):

            if re.compile("'.*?'").match(value) or re.compile("\s'.*?'").match(value):

              for msg in re.findall("'(.*?)'",value):
                outFile.write(msg+"\n")
            		
            else:
            	for msg in re.findall("'(.*?)'", value):

            		if re.compile('.*?"\s\+.*?".*?').match(msg):
            			pass
            		elif re.compile('(?i)(s|ve|re|m|d|re|t).*?').match(msg):
            			pass
            		else:
            			outFile.write(msg+"\n")
      	
      elif line.startswith("}"):
        	search = True


OutputExtract("samples/account_admin_abc123.nasl")
OutputExtract("samples/adobe_audition_installed.nasl")
OutputExtract("samples/ftp_administrator.nasl")
OutputExtract("samples/ftp_backdoor.nasl")
OutputExtract("samples/ftp_check_user.nasl")
OutputExtract("samples/ftp_novell_dos.nasl")
OutputExtract("samples/ftp_overflow.nasl")
OutputExtract("samples/ftp_servu_dos2.nasl")
OutputExtract("samples/ftp_site_exec.nasl")
OutputExtract("samples/phpmyadmin_pmasa_2013_15.nasl")
OutputExtract("samples/phpmyadmin_pmasa_2014_1.nasl")
OutputExtract("samples/smb_dom2sid.nasl")
OutputExtract("samples/test.txt")