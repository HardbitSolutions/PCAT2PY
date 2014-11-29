#!/usr/bin/python
################################################################################
# V38636
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/08/2014 Original construction
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
        return "SV-50437r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000159"
    
    def get_group_id(self):
        return "V-38636"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system must retain enough rotated audit logs to cover the required log retention period."
    
    def get_vulnerability_discussion(self):
        return "The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep num_logs /etc/audit/auditd.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("num_logs"):
                sub_string = (line.strip()).split('=')
                if int(sub_string[1]) >= 5:
                    self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i 's/^num_logs.*/num_logs = 5/g' /etc/audit/auditd.conf")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"