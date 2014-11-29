#!/usr/bin/python
################################################################################
# V38476
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/01/2014 Original construction
# 06/05/2014 os.popen and os.system replaced with paramiko
# 07/02/2014 Open check finding up to any gpg key
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
        return "SV-50276r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000008"
    
    def get_group_id(self):
        return "V-38476"
    
    def get_group_title(self):
        return "SRG-OS-000090"
    
    def get_rule_title(self):
        return "Vendor-provided cryptographic certificates must be installed to verify the integrity of system software."
    
    def get_vulnerability_discussion(self):
        return "This key is necessary to cryptographically verify packages are from Red Hat."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system('rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey')
        
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