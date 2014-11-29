#!/usr/bin/python
################################################################################
# V38531
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/16/2014 Original construction
# 06/17/2014 Corrected check method
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
        return "SV-50332r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000174"
    
    def get_group_id(self):
        return "V-38531"
    
    def get_group_title(self):
        return "SRG-OS-000004"
    
    def get_rule_title(self):
        return "The operating system must automatically audit account creation."
    
    def get_vulnerability_discussion(self):
        return "In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        passwd_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/passwd /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                passwd_compliant = True
                
        shadow_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep etc/shadow /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                shadow_compliant = True
                
        group_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/group /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                group_compliant = True
                
        gshadow_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/gshadow /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                gshadow_compliant = True
                
        opasswd_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/security/opasswd /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                opasswd_compliant = True
        
        if passwd_compliant and shadow_compliant and group_compliant and gshadow_compliant and opasswd_compliant:
            self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('echo "-w /etc/group -p wa -k audit_account_changes" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/passwd -p wa -k audit_account_changes" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/gshadow -p wa -k audit_account_changes" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/shadow -p wa -k audit_account_changes" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/security/opasswd -p wa -k audit_account_changes" >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"