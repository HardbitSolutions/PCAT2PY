#!/usr/bin/python
################################################################################
# V38549
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
        return "SV-50350r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000103"
    
    def get_group_id(self):
        return "V-38549"
    
    def get_group_title(self):
        return "SRG-OS-000152"
    
    def get_rule_title(self):
        return "The system must employ a local IPv6 firewall."
    
    def get_vulnerability_discussion(self):
        return "The ""ip6tables"" service provides the system's host-based firewalling capability for IPv6 and ICMPv6."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("service ip6tables status")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("ip6tables: Firewall is not running."):
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("chkconfig ip6tables on")
        cli.system("service ip6tables start")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"