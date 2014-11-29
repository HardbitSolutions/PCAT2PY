#!/usr/bin/python
################################################################################
# V38471
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/19/2014 Original construction
# 06/19/2014 Fixed regular expression in fix method
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
        return "SV-50271r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000509"
    
    def get_group_id(self):
        return "V-38471"
    
    def get_group_title(self):
        return "SRG-OS-000043"
    
    def get_rule_title(self):
        return "The system must forward audit records to the syslog service."
    
    def get_vulnerability_discussion(self):
        return "The auditd service does not include the ability to send audit records to a centralized server for management directly. It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep active /etc/audisp/plugins.d/syslog.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("active = yes"):
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i 's/active = .*/active = yes/g' /etc/audisp/plugins.d/syslog.conf")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"