#!/usr/bin/python
################################################################################
# V38475
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/07/2014 Original construction
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
        return "SV-50272r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000050"
    
    def get_group_id(self):
        return "V-38475"
    
    def get_group_title(self):
        return "SRG-OS-000078"
    
    def get_rule_title(self):
        return "The system must require passwords to contain a minimum of 14 characters."
    
    def get_vulnerability_discussion(self):
        return "Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep PASS_MIN_LEN /etc/login.defs")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("PASS_MIN_LEN"):
                sub_string = (line[12:]).strip()
                if int(sub_string) >= 14:
                    self.__is_compliant = True
                
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN  14/g' /etc/login.defs")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"