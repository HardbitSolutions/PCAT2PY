#!/usr/bin/python
################################################################################
# V38617
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/09/2014 Original construction
# 09/04/2014 Updated check method to parse a list of ciphers and compare
#            elements against approved ciphers
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
        return "SV-50418r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000243"
    
    def get_group_id(self):
        return "V-38617"
    
    def get_group_title(self):
        return "SRG-OS-000169"
    
    def get_rule_title(self):
        return "The SSH daemon must be configured to use only FIPS 140-2 approved ciphers."
    
    def get_vulnerability_discussion(self):
        return "Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep Ciphers /etc/ssh/sshd_config")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("Ciphers"):
                ciphers = line[7:].strip(' ').split(',')
                
                # Remove approved ciphers from list
                ciphers.remove('aes128-ctr')
                ciphers.remove('aes192-ctr')
                ciphers.remove('aes256-ctr')
                ciphers.remove('aes128-cbc')
                ciphers.remove('3des-cbc')
                ciphers.remove('aes192-cbc')
                ciphers.remove('aes256-cbc')
                
                # If there are no remaining ciphers then finding is compliant
                if len(ciphers) == 0:
                    self.__is_compliant = True
        
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"