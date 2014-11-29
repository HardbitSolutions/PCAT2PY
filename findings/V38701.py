#!/usr/bin/python
################################################################################
# V38701
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/02/2014 Original construction
# 06/06/2014 os.popen and os.system replaced with paramiko
################################################################################

class Finding:
    # Initialize compliance
    def __init__(self):
        self.__verbose = False
        self.__output = []
        self.__is_compliant = []
    
    def get_verbose(self):
        return self.__verbose
    
    def get_output(self):
        return self.__output
    
    def get_severity(self):
        return "CAT I"
    
    def get_rule_id(self):
        return "SV-50502r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000338"
    
    def get_group_id(self):
        return "V-38701"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system."
    
    def get_vulnerability_discussion(self):
        return "Using the ""-s"" option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system('grep "server_args" /etc/xinetd.d/tftp')
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if len(line.strip()) > 0 and "server_args = -s /var/lib/tftpboot" not in line:
                self.__is_compliant = False
                
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"