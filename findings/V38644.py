#!/usr/bin/python
################################################################################
# V38644
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
        return "SV-50445r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000265"
    
    def get_group_id(self):
        return "V-38644"
    
    def get_group_title(self):
        return "SRG-OS-000096"
    
    def get_rule_title(self):
        return "The ntpdate service must not be running."
    
    def get_vulnerability_discussion(self):
        return "The ""ntpdate"" service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("chkconfig ntpdate --list")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if ":on" in line:
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("chkconfig ntpdate off")
        cli.system("service ntpdate stop")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"