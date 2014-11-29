#!/usr/bin/python
################################################################################
# V38566
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
        return "SV-50367r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000197"
    
    def get_group_id(self):
        return "V-38566"
    
    def get_group_title(self):
        return "SRG-OS-000064"
    
    def get_rule_title(self):
        return "The audit system must be configured to audit failed attempts to access files and programs."
    
    def get_vulnerability_discussion(self):
        return "Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/audit/audit.rules")
        
        if "EACCES" in stdout and "EPERM" in stdout:
            self.__is_compliant = True
                
        return self.__is_compliant
    
    def fix(self, cli):
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/audit/audit.rules")
        
        if "EACCES" not in stdout:
            if "x86_64" in cli.system("uname -p"):
                cli.system('echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules')
                cli.system('echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access" >> /etc/audit/audit.rules')
            else:
                cli.system('echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules')
                cli.system('echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access" >> /etc/audit/audit.rules')
                
        if "EPERM" not in stdout:
            if "x86_64" in cli.system("uname -p"):
                cli.system('echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules')
                cli.system('echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access" >> /etc/audit/audit.rules')
            else:
                cli.system('echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules')
                cli.system('echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access" >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"