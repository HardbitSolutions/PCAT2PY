#!/usr/bin/python
################################################################################
# V38501
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/12/2014 Original construction
# 06/29/2014 Rewrote fix method
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
        return "SV-50302r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000357"
    
    def get_group_id(self):
        return "V-38501"
    
    def get_group_title(self):
        return "SRG-OS-000249"
    
    def get_rule_title(self):
        return "The system must disable accounts after excessive login failures within a 15-minute interval."
    
    def get_vulnerability_discussion(self):
        return "Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep pam_faillock /etc/pam.d/system-auth-ac")
        stdout += cli.system("grep pam_faillock /etc/pam.d/password-auth-ac")

        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "fail_interval" in line:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('echo "auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900" >> /etc/pam.d/system-auth-ac')
        cli.system('echo "auth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900" >> /etc/pam.d/system-auth-ac')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"