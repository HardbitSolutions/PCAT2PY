#!/usr/bin/python
################################################################################
# V38700
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/10/2014 Original construction
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
        return "SV-50501r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000305"
    
    def get_group_id(self):
        return "V-38700"
    
    def get_group_title(self):
        return "SRG-OS-000196"
    
    def get_rule_title(self):
        return "The operating system must provide a near real-time alert when any of the organization defined list of compromise or potential compromise indicators occurs. "
    
    def get_vulnerability_discussion(self):
        return "By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep aide /etc/crontab")
        
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
        cli.system('echo "0 0 * * * root /usr/sbin/aide --check" >> /etc/crontab')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"