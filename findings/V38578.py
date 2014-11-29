#!/usr/bin/python
################################################################################
# V38578
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
        return "SV-50379r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000201"
    
    def get_group_id(self):
        return "V-38578"
    
    def get_group_title(self):
        return "SRG-OS-000064"
    
    def get_rule_title(self):
        return "The audit system must be configured to audit changes to the /etc/sudoers file."
    
    def get_vulnerability_discussion(self):
        return "The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/audit/audit.rules")
        
        if "/etc/sudoers" in stdout:
            self.__is_compliant = True
                
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('echo "-w /etc/sudoers -p wa -k actions" >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"