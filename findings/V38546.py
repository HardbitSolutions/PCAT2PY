#!/usr/bin/python
################################################################################
# V38546
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/07/2014 Original construction
# 09/03/2014 Fixed grep command for the existence modprobe.conf and modprobe.d
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
        return "SV-50347r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000098"
    
    def get_group_id(self):
        return "V-38546"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The IPv6 protocol handler must not be bound to the network stack unless needed."
    
    def get_vulnerability_discussion(self):
        return "Any unnecessary network stacks - including IPv6 - should be disabled, to reduce the vulnerability to exploitation."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep -r ipv6 /etc/modprobe.conf")
        stdout += cli.system("grep -r ipv6 /etc/modprobe.d")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("options ipv6 disable"):
                sub_string = (line.strip()).split('=')
                if int(sub_string[1]) == 1:
                    self.__is_compliant = True
        
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"