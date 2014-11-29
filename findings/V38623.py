#!/usr/bin/python
################################################################################
# V38623
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/08/2014 Original construction
# 07/02/2014 Removed boot.log from check and fix methods
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
        return "SV-50424r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000135"
    
    def get_group_id(self):
        return "V-38623"
    
    def get_group_title(self):
        return "SRG-OS-000206"
    
    def get_rule_title(self):
        return "All rsyslog-generated log files must have mode 0600 or less permissive."
    
    def get_vulnerability_discussion(self):
        return "Log files can contain valuable information regarding system configuration. If the system log files are not protected, unauthorized users could change the logged data, eliminating their forensic value."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("ls -lL /var/log/messages")
        stdout += cli.system("ls -lL /var/log/secure")
        stdout += cli.system("ls -lL /var/log/maillog")
        stdout += cli.system("ls -lL /var/log/cron")
        stdout += cli.system("ls -lL /var/log/spooler")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                sub_string = (line.strip()).split(' ')
                if not "-rw-------" in sub_string[0]:
                    self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("chmod 600 /var/log/messages")
        cli.system("chmod 600 /var/log/secure")
        cli.system("chmod 600 /var/log/maillog")
        cli.system("chmod 600 /var/log/cron")
        cli.system("chmod 600 /var/log/spooler")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"