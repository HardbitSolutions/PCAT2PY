#!/usr/bin/python
################################################################################
# V38438
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/19/2014 Original construction
# 06/20/2014 Fixed fix method
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
        return "SV-50238r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000525"
    
    def get_group_id(self):
        return "V-38438"
    
    def get_group_title(self):
        return "SRG-OS-000062"
    
    def get_rule_title(self):
        return "Auditing must be enabled at boot by setting a kernel parameter."
    
    def get_vulnerability_discussion(self):
        return "Each process on the system carries an ""auditable"" flag which indicates whether its activities can be audited. Although ""auditd"" takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep kernel /etc/grub.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "audit=1" in line:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        # Desired value pair setting
        value_pair = "audit=1"
        sub_string = value_pair.split("=")
        name = sub_string[0]
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/grub.conf")
        
        # Clear existing grub.conf
        cli.system("/dev/null > /etc/grub.conf")
        
        # Split output lines
        output = stdout.split('\n')

        # Process standard output
        for line in output:
            kernel_line = ""
            
            if not line.startswith("#") and "kernel" in line:
                sub_string = (line.strip()).split(" ")
                
                for string in sub_string:
                    if name not in string:
                        kernel_line += string + " "
                
                kernel_line += value_pair
                
                cli.system('echo "' + kernel_line + '" >> /etc/grub.conf')
            else:
                cli.system('echo "' + line + '" >> /etc/grub.conf')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"