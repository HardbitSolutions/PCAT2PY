#!/usr/bin/python
################################################################################
# V38492
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
        return "SV-50293r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000027"
    
    def get_group_id(self):
        return "V-38492"
    
    def get_group_title(self):
        return "SRG-OS-000109"
    
    def get_rule_title(self):
        return "The system must prevent the root account from logging in from virtual consoles."
    
    def get_vulnerability_discussion(self):
        return "Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account. "
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep '^vc/[0-9]' /etc/securetty")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if "vc/" in line:
                self.__is_compliant = False
                
        return self.__is_compliant
    
    def fix(self, cli):
        # Execute command and parse capture standard output
        stdout = cli.system("grep '^vc/[0-9]' /etc/securetty")
        
        # Split output lines
        output = stdout.split('\n')

        # Remove detected virtual consoles
        for line in output:
            if len(line.strip()) > 0:
                fixCommand = "sed -i '\#" + line.strip() + "#d' /etc/securetty"
                cli.system(fixCommand)
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"