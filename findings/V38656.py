#!/usr/bin/python
################################################################################
# V38656
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/19/2014 Original construction
# 06/20/2014 Check if samba is installed
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
        return "SV-50457r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000272"
    
    def get_group_id(self):
        return "V-38656"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The system must use SMB client signing for connecting to samba servers using smbclient."
    
    def get_vulnerability_discussion(self):
        return "Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        samba_installed = False
        
        # Execute command and parse capture standard output
        stdout = cli.system('find /etc/samba -name smb.conf')
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        line_number = 0	
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if len(line.strip()) > 0:
                samba_installed = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep signing /etc/samba/smb.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        for line in self.__output:
            line_number += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(line_number) + ": " + line)	
            
            if line.startswith("client signing = mandatory"):
                self.__is_compliant = True
        
        if not samba_installed:
            self.__is_compliant = True
            
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i '/client signing/d' /etc/samba/smb.conf")
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/samba/smb.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        cli.system("/dev/null > /etc/samba/smb.conf")
        for line in self.__output:
            cli.system('echo "' + line + '" >> /etc/samba/smb.conf')
            
            if line.startswith("[global]"):
                cli.system('echo "client signing = mandatory" >> /etc/samba/smb.conf')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"