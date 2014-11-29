#!/usr/bin/python
################################################################################
# V38680
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/11/2014 Original construction
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
        return "SV-50481r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000313"
    
    def get_group_id(self):
        return "V-38680"
    
    def get_group_title(self):
        return "SRG-OS-000046"
    
    def get_rule_title(self):
        return "The audit system must identify staff members to receive notifications of audit log storage volume capacity issues."
    
    def get_vulnerability_discussion(self):
        return "Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep action_mail_acct /etc/audit/auditd.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("action_mail_acct = root"):
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('echo "action_mail_acct = root" >> /etc/audit/auditd.conf')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"