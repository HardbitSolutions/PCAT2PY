#!/usr/bin/python
################################################################################
# V38687
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/19/2014 Original construction
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
        return "SV-50488r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000321"
    
    def get_group_id(self):
        return "V-38687"
    
    def get_group_title(self):
        return "SRG-OS-000160"
    
    def get_rule_title(self):
        return "The system must provide VPN connectivity for communications over untrusted networks."
    
    def get_vulnerability_discussion(self):
        return "Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("rpm -q openswan")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "is not installed" in line:
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("yum -y -q install openswan")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"