#!/usr/bin/python
################################################################################
# V38485
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/12/2014 Original construction
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
        return "SV-50286r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000506"
    
    def get_group_id(self):
        return "V-38485"
    
    def get_group_title(self):
        return "SRG-OS-000025"
    
    def get_rule_title(self):
        return "The operating system, upon successful logon, must display to the user the date and time of the last logon or access via a local console or tty."
    
    def get_vulnerability_discussion(self):
        return "Users need to be aware of activity that occurs regarding their accounts. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("find / -name .hushlogin")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        # Execute command and parse capture standard output
        stdout = cli.system("find / -name .hushlogin")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        for line in self.__output:
            if len(line.strip()) > 0:
                cli.system("rm -f " + line.strip())
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"