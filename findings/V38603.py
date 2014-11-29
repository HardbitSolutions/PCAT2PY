#!/usr/bin/python
################################################################################
# V38603
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
        return "SV-50404r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000220"
    
    def get_group_id(self):
        return "V-38603"
    
    def get_group_title(self):
        return "SRG-OS-000095"
    
    def get_rule_title(self):
        return "The ypserv package must not be installed."
    
    def get_vulnerability_discussion(self):
        return "Removing the ""ypserv"" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("rpm -q ypserv")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "package ypserv is not installed" in line:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("yum -y -q erase ypserv")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"