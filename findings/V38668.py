#!/usr/bin/python
################################################################################
# V38668
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
        return "SV-50469r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000286"
    
    def get_group_id(self):
        return "V-38668"
    
    def get_group_title(self):
        return "SRG-OS-999999"
    
    def get_rule_title(self):
        return "The x86 Ctrl-Alt-Delete key sequence must be disabled."
    
    def get_vulnerability_discussion(self):
        return "A locally logged-in user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken."
  
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/init/control-alt-delete.conf")
        
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        lineNumber = 0	
        for line in self.__output:
            lineNumber += 1
        
            if self.__verbose:
                print("STDOUT LINE " + str(lineNumber) + ": " + line)	
            
            if "exec /sbin/shutdown -r now" in line:
                self.__is_compliant = False
                
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("sed -i '/^exec/d' /etc/init/control-alt-delete.conf")
        cli.system('echo "exec /usr/bin/logger -p security.info Ctrl-Alt-Delete pressed" > /etc/init/control-alt-delete.conf')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"