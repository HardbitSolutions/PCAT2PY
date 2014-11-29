#!/usr/bin/python
################################################################################
# V38590
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/16/2014 Original construction
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
        return "SV-50391r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000071"
    
    def get_group_id(self):
        return "V-38590"
    
    def get_group_title(self):
        return "SRG-OS-000030"
    
    def get_rule_title(self):
        return "The system must allow locking of the console screen in text mode."
    
    def get_vulnerability_discussion(self):
        return "Installing ""screen"" ensures a console locking capability is available for users who may need to suspend console logins."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("rpm -q screen")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "package screen is not installed" in line:
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("yum -y -q install screen")    
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"