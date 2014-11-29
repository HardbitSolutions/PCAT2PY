#!/usr/bin/python
################################################################################
# V38579
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
        return "SV-50380r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000065"
    
    def get_group_id(self):
        return "V-38579"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system boot loader configuration file(s) must be owned by root."
    
    def get_vulnerability_discussion(self):
        return "Only root should be able to modify important boot parameters."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("ls -lL /etc/grub.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                sub_string = (line.strip()).split(' ')
                if sub_string[2] == "root":
                    self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("chown root /etc/grub.conf")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"