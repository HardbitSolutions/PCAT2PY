#!/usr/bin/python
################################################################################
# V38658
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/10/2014 Original construction
# 06/28/2014 Added fix method
# 09/04/2014 Add system-auth-ac to check method
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
        return "SV-50459r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000274"
    
    def get_group_id(self):
        return "V-38658"
    
    def get_group_title(self):
        return "SRG-OS-000077"
    
    def get_rule_title(self):
        return "The system must prohibit the reuse of passwords within twenty-four iterations."
    
    def get_vulnerability_discussion(self):
        return "Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep remember /etc/pam.d/system-auth")
        stdout += cli.system("grep remember /etc/pam.d/system-auth-ac")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "remember=24" in line and line.startswith("password"):
                self.__is_compliant = True
                 
        return self.__is_compliant
    
    def fix(self, cli):
        # Desired PAM setting
        value_pair = "remember=24"
        sub_string = value_pair.split("=")
        name = sub_string[0]
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep 'password' /etc/pam.d/system-auth")
        
        # Split output lines
        output = stdout.split('\n')

        # Process standard output
        for line in output:
            password_pam_unix_line = ""
            
            if line.startswith("password") and "sufficient" in line and "pam_unix.so" in line:
                sub_string = (line.strip()).split(" ")
                
                for string in sub_string:
                    if name not in string:
                        password_pam_unix_line += string + " "
                
                password_pam_unix_line += value_pair
                
                cli.system("sed -i 's/" + line.strip() + "/" + password_pam_unix_line + "/' /etc/pam.d/system-auth")    
        
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"