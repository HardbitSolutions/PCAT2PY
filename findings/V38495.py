#!/usr/bin/python
################################################################################
# V38495
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
        return "SV-50296r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000384"
    
    def get_group_id(self):
        return "V-38495"
    
    def get_group_title(self):
        return "SRG-OS-000057"
    
    def get_rule_title(self):
        return "Audit log files must be owned by root."
    
    def get_vulnerability_discussion(self):
        return "If non-privileged users can write to audit logs, audit trails can be modified or destroyed."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system('grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U:%n')
      
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                sub_string = line.split(":")
                if "root" not in sub_string[0]:
                    self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        # Execute command and parse capture standard output
        stdout = cli.system('grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U:%n')
      
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        for line in self.__output:
            if len(line.strip()) > 0:
                sub_string = line.split(":")
                if "root" not in sub_string[0]:
                    cli.system("chown root " + sub_string[1])
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"