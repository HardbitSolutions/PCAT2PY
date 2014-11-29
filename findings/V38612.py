#!/usr/bin/python
################################################################################
# V38612
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/08/2014 Original construction
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
        return "SV-50413r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000236"
    
    def get_group_id(self):
        return "V-38612"
    
    def get_group_title(self):
        return "SRG-OS-000106"
    
    def get_rule_title(self):
        return "The SSH daemon must not allow host-based authentication."
    
    def get_vulnerability_discussion(self):
        return "SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep -i HostbasedAuthentication /etc/ssh/sshd_config")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("HostbasedAuthentication no"):
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i 's/^#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"