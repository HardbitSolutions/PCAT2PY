#!/usr/bin/python
################################################################################
# V38637
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/10/2014 Original construction
# 09/04/2014 Fixed quoting in regular expression for check method
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
        return "SV-50438r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000281"
    
    def get_group_id(self):
        return "V-38637"
    
    def get_group_title(self):
        return "SRG-OS-000278"
    
    def get_rule_title(self):
        return "The system package management tool must verify contents of all files associated with the audit package."
    
    def get_vulnerability_discussion(self):
        return "The hash on important files like audit system executables should match the information given by the RPM database. Audit executables with erroneous hashes could be a sign of nefarious activity on the system."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system(r"""rpm -V audit | awk '$1 ~ /..5/ && $2 != "c"'""")
        
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
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"