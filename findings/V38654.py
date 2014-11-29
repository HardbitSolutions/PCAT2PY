#!/usr/bin/python
################################################################################
# V38654
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/09/2014 Original construction
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
        return "SV-50455r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000270"
    
    def get_group_id(self):
        return "V-38654"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "Remote file systems must be mounted with the nosuid option."
    
    def get_vulnerability_discussion(self):
        return "NFS mounts should not present suid binaries to users. Only vendor-supplied suid executables should be installed to their default location on the local filesystem."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("mount | grep nfs")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0 and "nosuid" not in line:
                self.__is_compliant = False
        
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"