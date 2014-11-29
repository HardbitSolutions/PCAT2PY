#!/usr/bin/python
################################################################################
# V38540
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/17/2014 Original construction
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
        return "SV-50341r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000182"
    
    def get_group_id(self):
        return "V-38540"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The audit system must be configured to audit modifications to the systems network configuration."
    
    def get_vulnerability_discussion(self):
        return "The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        set_hostname_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep sethostname /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                set_hostname_compliant = True
                
        set_domain_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep setdomainname /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                set_domain_compliant = True
                
        issue_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/issue /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                issue_compliant = True
                
        issue_dot_net_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/issue.net /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                issue_dot_net_compliant = True
                
        hosts_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/hosts /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                hosts_compliant = True
        
        network_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep /etc/sysconfig/network /etc/audit/audit.rules")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                network_compliant = True
        
        if set_hostname_compliant and set_domain_compliant and issue_compliant and issue_dot_net_compliant and hosts_compliant and network_compliant:
            self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system('echo "-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/issue -p wa -k audit_network_modifications" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/issue.net -p wa -k audit_network_modifications" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/hosts -p wa -k audit_network_modifications" >> /etc/audit/audit.rules')
        cli.system('echo "-w /etc/sysconfig/network -p wa -k audit_network_modifications" >> /etc/audit/audit.rules')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"