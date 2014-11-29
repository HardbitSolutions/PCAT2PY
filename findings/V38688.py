#!/usr/bin/python
################################################################################
# V38688(2)
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/11/2014 Original construction
# 06/20/2014 Check if gnome is installed
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
        return "SV-50489r2_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000324"
    
    def get_group_id(self):
        return "V-38688"
    
    def get_group_title(self):
        return "SRG-OS-000024"
    
    def get_rule_title(self):
        return "A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts."
    
    def get_vulnerability_discussion(self):
        return "An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        gnome_installed = False
        
        # Execute command and parse capture standard output
        stdout = cli.system('find /etc/gconf -name gconf.xml.mandatory')
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                gnome_installed = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if "true" in line or not gnome_installed:
                self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gdm/simple-greeter/banner_message_enable true")
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"