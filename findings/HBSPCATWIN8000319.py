
#!/usr/bin/python
################################################################################
# V36692
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SZ EQ finding
#
# 09/21/2014 Original Construction
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
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-36692"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Remote assistance must display a warning message when allowing helpdesk personnel to control a system."

    def get_vulnerability_discussion(self):
        return r"Requiring warning text to display when allowing helpdesk personnel to control remote assistance sessions ensures personnel of the activity and enforces the need to monitor the activity. Set the policy value for Computer Configuration \ Administrative Templates \ System \ Remote Assistance \ ''Customize warning messages'' to ''Enabled'' with ''You are about to allow other personnel to remotely control your system.  You must monitor the activity until the session is closed.'' entered in the ''Display warning message before sharing control:'' field."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', 'ShareControlMessage')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', ('ShareControlMessage=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "You are about to allow other personnel to remotely control your system.  You must monitor the activity until the session is closed.":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -name 'ShareControlMessage' -value You are about to allow other personnel to remotely control your system.  You must monitor the activity until the session is closed.")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(A)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000319"
    
    def get_dod8500_2(self):
        return "ECWM-1"

    def get_800_53(self):
        return "AC-8"
    
    def get_iso_27001(self):
        return "A.6.2.2, A.11.5.1, A.15.1.5"