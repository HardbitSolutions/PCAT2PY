#!/usr/bin/python
################################################################################
# V38478
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/15/2014 Original construction
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
        return "SV-50278r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000009"
    
    def get_group_id(self):
        return "V-38604"
    
    def get_group_title(self):
        return "SRG-OS-000096"
    
    def get_rule_title(self):
        return "The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite."
    
    def get_vulnerability_discussion(self):
        return "Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system is being managed by RHN or RHN Satellite Server the ""rhnsd"" daemon can remain on."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("chkconfig rhnsd --list")
        
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
        cli.system("chkconfig rhnsd off")
        cli.system("service rhnsd stop")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"