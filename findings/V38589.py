#!/usr/bin/python
################################################################################
# V38589
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/01/2014 Original construction
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
        return "CAT I"
    
    def get_rule_id(self):
        return "SV-50390r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000211"
    
    def get_group_id(self):
        return "V-38589"
    
    def get_group_title(self):
        return "SRG-OS-000129"
    
    def get_rule_title(self):
        return "The telnet daemon must not be running."
    
    def get_vulnerability_discussion(self):
        return "The telnet protocol uses unencrypted network communication, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. The telnet protocol is also subject to man-in-the-middle attacks."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system('chkconfig "telnet" --list')
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if "telnet off" in line or "error reading information on service telnet: No such file or directory":    
                self.__is_compliant = True
                
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('chkconfig telnet off')      
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"