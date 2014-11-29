#!/usr/bin/python
################################################################################
# V38597
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/07/2014 Original construction
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
        return "SV-50398r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000079"
    
    def get_group_id(self):
        return "V-38597"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system must limit the ability of processes to have simultaneous write and execute access to memory."
    
    def get_vulnerability_discussion(self):
        return "ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("sysctl kernel.exec-shield")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if (line.strip()).startswith("kernel.exec-shield"):
                sub_string = (line.strip()).split('=')
                if int(sub_string[1]) == 1:
                    self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sysctl -w kernel.exec-shield=1")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"