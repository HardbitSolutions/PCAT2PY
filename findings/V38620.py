#!/usr/bin/python
################################################################################
# V38620
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/09/2014 Original construction
# 06/19/2014 Fixed check method cli command
# 06/20/2014 Added yum install to fix method
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
        return "SV-50421r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000227"
    
    def get_group_id(self):
        return "V-38620"
    
    def get_group_title(self):
        return "SRG-OS-000056"
    
    def get_rule_title(self):
        return "The system clock must be synchronized continuously, or at least daily."
    
    def get_vulnerability_discussion(self):
        return "Enabling the ""ntpd"" service ensures that the ""ntpd"" service will be running and that the system will synchronize its time to any servers specified. This is important whether the system is configured to be a client (and synchronize only its own clock) or it is also acting as an NTP server to other systems. Synchronizing time is essential for authentication services such as Kerberos, but it is also important for maintaining accurate logs and auditing possible security breaches."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("service ntpd status")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("ntpd") and "is running" in line:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("yum -q -y install ntpd")
        cli.system("chkconfig ntpd on")
        cli.system("service ntpd start")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"