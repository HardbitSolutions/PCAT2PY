#!/usr/bin/python
################################################################################
# V38569
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/15/2014 Original construction
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
        return "SV-50370r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000057"
    
    def get_group_id(self):
        return "V-38569"
    
    def get_group_title(self):
        return "SRG-OS-000069"
    
    def get_rule_title(self):
        return "The system must require passwords to contain at least one uppercase alphabetic character."
    
    def get_vulnerability_discussion(self):
        return "Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep pam_cracklib /etc/pam.d/system-auth")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("password") and "ucredit=-1" in line:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        # Desired PAM setting
        value_pair = "ucredit=-1"
        sub_string = value_pair.split("=")
        name = sub_string[0]
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep pam_cracklib /etc/pam.d/system-auth")
        
        # Split output lines
        output = stdout.split('\n')

        # Process standard output
        for line in output:
            password_pam_cracklib_line = ""
            
            if line.startswith("password"):
                sub_string = (line.strip()).split(" ")
                
                for string in sub_string:
                    if name not in string:
                        password_pam_cracklib_line += string + " "
                
                password_pam_cracklib_line += value_pair
                
                cli.system("sed -i 's/.*pam_cracklib.*/" + password_pam_cracklib_line + "/' /etc/pam.d/system-auth")    
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"