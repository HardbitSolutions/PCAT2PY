#!/usr/bin/python
################################################################################
# V38619
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/11/2014 Original construction
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
        return "SV-50420r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000347"
    
    def get_group_id(self):
        return "V-38619"
    
    def get_group_title(self):
        return "SRG-OS-000073"
    
    def get_rule_title(self):
        return "There must be no .netrc files on the system."
    
    def get_vulnerability_discussion(self):
        return "Unencrypted passwords for remote FTP servers may be stored in "".netrc"" files. DoD policy requires passwords be encrypted in storage and not used in access scripts."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("find /home -xdev -name .netrc")
        
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
        # Execute command and parse capture standard output
        stdout = cli.system("find /home -xdev -name .netrc")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        for line in self.__output:
            if len(line.strip()) > 0:
                fix_command = "rm -f " + line.strip()
                cli.system(fix_command)
        
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"