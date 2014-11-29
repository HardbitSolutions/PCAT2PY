#!/usr/bin/python
################################################################################
# V38472
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/04/2014 Original construction
# 06/05/2014 os.popen and os.system replaced with paramiko
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
        return "SV-50272r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000048"
    
    def get_group_id(self):
        return "V-38472"
    
    def get_group_title(self):
        return "SRG-OS-000259"
    
    def get_rule_title(self):
        return "All system command files must be owned by root."
    
    def get_vulnerability_discussion(self):
        return "System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("find -L /bin \! -user root")
        stdout += cli.system("find -L /usr/bin \! -user root")
        stdout += cli.system("find -L /usr/local/bin \! -user root")
        stdout += cli.system("find -L /sbin \! -user root")
        stdout += cli.system("find -L /usr/sbin \! -user root")
        stdout += cli.system("find -L /usr/local/sbin \! -user root")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if len(line.strip()) > 0:
                self.__is_compliant = False
                
        return self.__is_compliant
    
    def fix(self, cli):
        # Execute command and parse capture standard output
        stdout = cli.system("find -L /bin \! -user root")
        stdout += cli.system("find -L /usr/bin \! -user root")
        stdout += cli.system("find -L /usr/local/bin \! -user root")
        stdout += cli.system("find -L /sbin \! -user root")
        stdout += cli.system("find -L /usr/sbin \! -user root")
        stdout += cli.system("find -L /usr/local/sbin \! -user root")
        
        # Split output lines
        output = stdout.split('\n')
        
        # Process output
        for line in output:
            if len(line.strip()) > 0:
                fixCommand = "chown root " + line.strip()
                clis.system(fixCommand)
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"