#!/usr/bin/python
################################################################################
# V38479
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
        return "SV-50279r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000053"
    
    def get_group_id(self):
        return "V-38479"
    
    def get_group_title(self):
        return "SRG-OS-000076"
    
    def get_rule_title(self):
        return "User passwords must be changed at least every 60 days."
    
    def get_vulnerability_discussion(self):
        return "Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep PASS_MAX_DAYS /etc/login.defs")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("PASS_MAX_DAYS"):
                sub_string = (line[13:]).strip()
                if int(sub_string) <= 60:
                    self.__is_compliant = True
                
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS  60/g' /etc/login.defs")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"