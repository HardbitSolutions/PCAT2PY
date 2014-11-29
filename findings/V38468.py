#!/usr/bin/python
################################################################################
# V38468
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/15/2014 Original construction
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
        return "SV-50268r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000510"
    
    def get_group_id(self):
        return "V-38468"
    
    def get_group_title(self):
        return "SRG-OS-000047"
    
    def get_rule_title(self):
        return "The audit system must take appropriate action when the audit storage volume is full."
    
    def get_vulnerability_discussion(self):
        return "Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system('grep disk_full_action /etc/audit/auditd.conf')
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if line.startswith("disk_full_action = SYSLOG"):
                self.__is_compliant = True
            elif line.startswith("disk_full_action = EXEC"):
                self.__is_compliant = True
            elif line.startswith("disk_full_action = SINGLE"):
                self.__is_compliant = True
            elif line.startswith("disk_full_action = HALT"):
                self.__is_compliant = True
                
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"