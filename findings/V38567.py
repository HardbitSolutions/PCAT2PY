#!/usr/bin/python
################################################################################
# V38567
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
        return "SV-50368r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000198"
    
    def get_group_id(self):
        return "V-38567"
    
    def get_group_title(self):
        return "SRG-OS-000020"
    
    def get_rule_title(self):
        return "The audit system must be configured to audit all use of setuid programs."
    
    def get_vulnerability_discussion(self):
        return "Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("mount")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        mount_points = []
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                sub_string = (line.strip()).split(" ")
                mount_points.append(sub_string[2])
                
        stdout = ""
        for mount_point in mount_points:
            stdout += cli.system("find " + mount_point + " -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null")
            
        # Split output lines
        self.__output = stdout.split('\n')
            
        # Retreive existing audit rules into a string    
        audit_rules = cli.system("cat /etc/audit/audit.rules")
            
        # Process standard output
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.strip() not in audit_rules:
                self.__is_compliant = False
                
        return self.__is_compliant
    
    def fix(self, cli):
        # Execute command and parse capture standard output
        stdout = cli.system("mount")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        mount_points = []
        for line in self.__output:
            if len(line.strip()) > 0:
                sub_string = (line.strip()).split(" ")
                mount_points.append(sub_string[2])
                
        stdout = ""
        for mount_point in mount_points:
            stdout += cli.system("find " + mount_point + " -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null")
            
        # Split output lines
        self.__output = stdout.split('\n')
            
        # Retreive existing audit rules into a string    
        audit_rules = cli.system("cat /etc/audit/audit.rules")
            
        # Process standard output
        for line in self.__output:
            if line.strip() not in audit_rules:
                cli.system('echo "-a always,exit -F path=' + line.strip() + ' -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"