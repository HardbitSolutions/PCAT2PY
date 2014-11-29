#!/usr/bin/python
################################################################################
# V38573
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
        return "SV-50374r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000061"
    
    def get_group_id(self):
        return "V-38573"
    
    def get_group_title(self):
        return "SRG-OS-000021"
    
    def get_rule_title(self):
        return "The system must disable accounts after three consecutive unsuccessful login attempts."
    
    def get_vulnerability_discussion(self):
        return "Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep pam_faillock /etc/pam.d/system-auth-ac")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        system_auth_ac_deny_3 = False
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "deny=3" in line and line.startswith("auth"):
                system_auth_ac_deny_3 = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep pam_faillock /etc/pam.d/password-auth-ac")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        password_auth_ac_deny_3 = False
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "deny=3" in line and line.startswith("auth"):
                password_auth_ac_deny_3 = True
        
        if password_auth_ac_deny_3 and system_auth_ac_deny_3:
                self.__is_compliant = True
                
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"