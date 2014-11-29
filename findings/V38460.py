#!/usr/bin/python
################################################################################
# V38460
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
        return "SV-50260r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000515"
    
    def get_group_id(self):
        return "V-38460"
    
    def get_group_title(self):
        return "SRG-OS-000104"
    
    def get_rule_title(self):
        return "The NFS server must not have the all_squash option enabled."
    
    def get_vulnerability_discussion(self):
        return "The ""all_squash"" option maps all client requests to a single anonymous uid/gid on the NFS server, negating the ability to track file access by user ID."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep all_squash /etc/exports")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("service nfs restart")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"