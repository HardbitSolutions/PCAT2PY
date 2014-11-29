#!/usr/bin/python
################################################################################
# V38624
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/16/2014 Original construction
# 06/20/2014 Added find for /etc/cron* logrotate
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
        return "SV-50425r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000138"
    
    def get_group_id(self):
        return "V-38624"
    
    def get_group_title(self):
        return "SRG-OS-000138"
    
    def get_rule_title(self):
        return "System logs must be rotated daily."
    
    def get_vulnerability_discussion(self):
        return "Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep logrotate /var/log/cron*")
        stdout += cli.system("find /etc/cron* -name logrotate")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("yum -q -y reinstall logrotate")    
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"