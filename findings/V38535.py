#!/usr/bin/python
################################################################################
# V38535
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/16/2014 Original construction
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
        return "CAT III"
    
    def get_rule_id(self):
        return "SV-50336r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000092"
    
    def get_group_id(self):
        return "V-38535"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system must not respond to ICMPv4 sent to a broadcast address."
    
    def get_vulnerability_discussion(self):
        return "Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("sysctl net.ipv4.icmp_echo_ignore_broadcasts")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "net.ipv4.icmp_echo_ignore_broadcasts = 1" in line:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1")
        cli.system("sed -i '/^net.ipv4.icmp_echo_ignore_broadcasts.*/d' /etc/sysctl.conf")
        cli.system('echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"