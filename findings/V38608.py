#!/usr/bin/python
################################################################################
# V38608
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
        return "SV-50409r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000230"
    
    def get_group_id(self):
        return "V-38608"
    
    def get_group_title(self):
        return "SRG-OS-000163"
    
    def get_rule_title(self):
        return "The SSH daemon must set a timeout interval on idle sessions."
    
    def get_vulnerability_discussion(self):
        return "Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep ClientAliveInterval /etc/ssh/sshd_config")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("ClientAliveInterval 900"):
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i '/ClientAliveInterval/d' /etc/ssh/sshd_config")
        cli.system('echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"