#!/usr/bin/python
################################################################################
# V38574
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/07/2014 Original construction
# 09/03/2014 Added system-auth-ac from sha512 grep
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
        return "SV-50375r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000062"
    
    def get_group_id(self):
        return "V-38574"
    
    def get_group_title(self):
        return "SRG-OS-000062"
    
    def get_rule_title(self):
        return "The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth)."
    
    def get_vulnerability_discussion(self):
        return "Using a stronger hashing algorithm makes password cracking attacks more difficult."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep sha512 /etc/pam.d/system-auth")
        stdout += cli.system("grep sha512 /etc/pam.d/system-auth-ac")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant
    def get_posture(self):
        return "RHEL6"