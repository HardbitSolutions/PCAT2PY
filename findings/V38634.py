#!/usr/bin/python
################################################################################
# V38634
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
        return "SV-50435r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000161"
    
    def get_group_id(self):
        return "V-38634"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system must rotate audit log files that reach the maximum file size."
    
    def get_vulnerability_discussion(self):
        return "Automatically rotating logs (by setting this to ""rotate"") minimizes the chances of the system unexpectedly running out of disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use external processes to transfer it and reclaim space, ""keep_logs"" can be employed."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep max_log_file_action /etc/audit/auditd.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("max_log_file_action"):
                sub_string = (line.strip()).split('=')
                if "ROTATE" in sub_string[1]:
                    self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i 's/^max_log_file_action.*/max_log_file_action = ROTATE/g' /etc/audit/auditd.conf")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"