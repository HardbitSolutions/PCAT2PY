#!/usr/bin/python
################################################################################
# V38694
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/19/2014 Original construction
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
        return "CAT III"
    
    def get_rule_id(self):
        return "SV-50495r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000335"
    
    def get_group_id(self):
        return "V-38694"
    
    def get_group_title(self):
        return "SRG-OS-000118"
    
    def get_rule_title(self):
        return "The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity."
    
    def get_vulnerability_discussion(self):
        return "Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep INACTIVE /etc/default/useradd")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("INACTIVE=35"):
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i '/INACTIVE/d' /etc/default/useradd")
        cli.system('echo "INACTIVE=35" >> /etc/default/useradd')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"