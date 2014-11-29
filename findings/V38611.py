#!/usr/bin/python
################################################################################
# V38611
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/08/2014 Original construction
# 06/19/2014 Fixed regular expression if fix method
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
        return "SV-50412r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000234"
    
    def get_group_id(self):
        return "V-38611"
    
    def get_group_title(self):
        return "SRG-OS-000106"
    
    def get_rule_title(self):
        return "The SSH daemon must ignore .rhosts files."
    
    def get_vulnerability_discussion(self):
        return "SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep -i IgnoreRhosts /etc/ssh/sshd_config")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("IgnoreRhosts yes"):
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i 's/.*IgnoreRhosts.*/IgnoreRhosts yes/g' /etc/ssh/sshd_config")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"