#!/usr/bin/python
################################################################################
# V38450
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/04/2014 Original construction
# 06/05/2014 os.popen and os.system replaced with paramiko
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
        return "CAT II"
    
    def get_rule_id(self):
        return "SV-50250r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000039"
    
    def get_group_id(self):
        return "V-38450"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The /etc/passwd file must be owned by root."
    
    def get_vulnerability_discussion(self):
        return "The ""/etc/passwd"" file contains information about the users that are configured on the system. Protection of this file is critical for system security."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("ls -l /etc/passwd")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if len(line.strip()) > 0:
                subStrings = line.split(' ')
                if subStrings[2] == "root":
                    self.__is_compliant = True
                
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("chown root /etc/passwd")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"