#!/usr/bin/python
################################################################################
# V38941
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/01/2014 Original construction
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
        return "SV-50292r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000019"
    
    def get_group_id(self):
        return "V-38491"
    
    def get_group_title(self):
        return "SRG-OS-000248"
    
    def get_rule_title(self):
        return "There must be no .rhosts or hosts.equiv files on the system."
    
    def get_vulnerability_discussion(self):
        return "Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system('find /etc -name hosts.equiv')
        stdout += cli.system('find /home -name *.rhosts')
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if len(line.strip()) > 0:    
                self.__is_compliant = False
                
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('rm /etc/hosts.equiv')
        cli.system('rm ~/.rhosts')        
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"