#!/usr/bin/python
################################################################################
# V38682
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/11/2014 Original construction
# 06/20/2014 Adjusted code to use blacklisting in /etc/modprobe.d/blacklist.conf
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
        return "SV-50483r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000315"
    
    def get_group_id(self):
        return "V-38682"
    
    def get_group_title(self):
        return "SRG-OS-000034"
    
    def get_rule_title(self):
        return "The Bluetooth kernel module must be disabled."
    
    def get_vulnerability_discussion(self):
        return "If Bluetooth functionality must be disabled, preventing the kernel from loading the kernel module provides an additional safeguard against its activation."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep bluetooth /etc/modprobe.d/blacklist.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        bluetooth = False
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                bluetooth = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep net-pf-31 /etc/modprobe.d/blacklist.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        net_pf_31 = False
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                net_pf_31 = True
        
        if bluetooth and net_pf_31:
            self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('echo "blacklist net-pf-31" >> /etc/modprobe.d/blacklist.conf')
        cli.system('echo "blacklist bluetooth" >> /etc/modprobe.d/blacklist.conf')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"