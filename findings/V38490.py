#!/usr/bin/python
################################################################################
# V38490
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/12/2014 Original construction
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
        return "SV-50291r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000503"
    
    def get_group_id(self):
        return "V-38490"
    
    def get_group_title(self):
        return "SRG-OS-000273"
    
    def get_rule_title(self):
        return "The operating system must enforce requirements for the connection of mobile devices to operating systems."
    
    def get_vulnerability_discussion(self):
        return "USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"