#!/usr/bin/python
################################################################################
# V38666
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/02/2014 Original construction
# 06/06/2014 os.popen and os.system replaced with paramiko
# 07/02/2014 Simplified check method to global find for avvnames.dat
# 08/08/2014 Removed mtime switch from find
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
        return "CAT I"
    
    def get_rule_id(self):
        return "SV-50467r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000284"
    
    def get_group_id(self):
        return "V-38666"
    
    def get_group_title(self):
        return "SRG-OS-000270"
    
    def get_rule_title(self):
        return "The system must use and update a DoD-approved virus scan program."
    
    def get_vulnerability_discussion(self):
        return "Virus scanning software can be used to detect if a system has been compromised by computer viruses, as well as to limit their spread to other systems."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system('find / -name avvnames.dat')
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = True
            
        return self.__is_compliant
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"