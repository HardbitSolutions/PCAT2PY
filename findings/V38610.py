#!/usr/bin/python
################################################################################
# V38610
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
        return "SV-50411r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000231"
    
    def get_group_id(self):
        return "V-38610"
    
    def get_group_title(self):
        return "SRG-OS-000126"
    
    def get_rule_title(self):
        return "The SSH daemon must set a timeout count on idle sessions."
    
    def get_vulnerability_discussion(self):
        return "This ensures a user login will be terminated as soon as the ""ClientAliveCountMax"" is reached."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep ClientAliveCountMax /etc/ssh/sshd_config")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("ClientAliveCountMax 0"):
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i '/ClientAliveCountMax/d' /etc/ssh/sshd_config")
        cli.system('echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"