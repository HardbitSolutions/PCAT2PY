#!/usr/bin/python
################################################################################
# V38529
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/07/2014 Original construction
# 06/28/2014 Modified fix method to include editing /etc/sysctl.conf.
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
        return "SV-50330r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000089"
    
    def get_group_id(self):
        return "V-38529"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system must not accept IPv4 source-routed packets by default."
    
    def get_vulnerability_discussion(self):
        return "Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("sysctl net.ipv4.conf.default.accept_source_route")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("net.ipv4.conf.default.accept_source_route"):
                sub_string = (line.strip()).split('=')
                if int(sub_string[1]) == 0:
                    self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sysctl -w net.ipv4.conf.default.accept_source_route=0")
        cli.system("sed -i '/^net.ipv4.conf.default.accept_source_route.*/d' /etc/sysctl.conf")
        cli.system('echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"