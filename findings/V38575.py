#!/usr/bin/python
################################################################################
# V38575
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
        return "SV-50376r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000200"
    
    def get_group_id(self):
        return "V-38575"
    
    def get_group_title(self):
        return "SRG-OS-000064"
    
    def get_rule_title(self):
        return "The audit system must be configured to audit user deletions of files and programs."
    
    def get_vulnerability_discussion(self):
        return "Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/audit/audit.rules")
        
        if "unlink" in stdout and "unlinkat" in stdout and "rename" in stdout and "renameat" in stdout:
            self.__is_compliant = True
                
        return self.__is_compliant
    
    def fix(self, cli):
        if "x86_64" in cli.system("uname -p"):
            cli.system('echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules')
            cli.system('echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete   " >> /etc/audit/audit.rules')
        else:
            cli.system('echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules')
            cli.system('echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete   " >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"