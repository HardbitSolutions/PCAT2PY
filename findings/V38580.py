#!/usr/bin/python
################################################################################
# V38580
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/08/2014 Original construction
# 06/19/2014 Corrected fix method to handle multiple architectures
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
        return "SV-50381r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000202"
    
    def get_group_id(self):
        return "V-38580"
    
    def get_group_title(self):
        return "SRG-OS-000064"
    
    def get_rule_title(self):
        return "The audit system must be configured to audit the loading and unloading of dynamic kernel modules."
    
    def get_vulnerability_discussion(self):
        return "The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        if "init_module" in stdout and "delete_module" in stdout:
            self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules')
        cli.system('echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules')
        cli.system('echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules')
        
        if "x86_64" in cli.system("uname -p"):
            cli.system('echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules')
        else:
            cli.system('echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"