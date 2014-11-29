#!/usr/bin/python
################################################################################
# V38560
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
        return "SV-50361r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000116"
    
    def get_group_id(self):
        return "V-38560"
    
    def get_group_title(self):
        return "SRG-OS-000145"
    
    def get_rule_title(self):
        return "The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture."
    
    def get_vulnerability_discussion(self):
        return "The ""iptables"" service provides the system's host-based firewalling capability for IPv4 and ICMP."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("service iptables status")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("iptables: Firewall is not running."):
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("chkconfig iptables on")
        cli.system("service iptables start")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"