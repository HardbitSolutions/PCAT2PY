#!/usr/bin/python
################################################################################
# V38525
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
        return "SV-50326r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000169"
    
    def get_group_id(self):
        return "V-38525"
    
    def get_group_title(self):
        return "SRG-OS-000062"
    
    def get_rule_title(self):
        return "The audit system must be configured to audit all attempts to alter system time through stime."
    
    def get_vulnerability_discussion(self):
        return "Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep stime /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        if "x86_64" in cli.system("uname -p"):
            cli.system('echo "-a always,exit -F arch=b64 -S stime -k audit_time_rules" >> /etc/audit/audit.rules')
        else:
            cli.system('echo "-a always,exit -F arch=b32 -S stime -k audit_time_rules" >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"