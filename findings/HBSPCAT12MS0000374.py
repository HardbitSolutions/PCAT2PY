
#!/usr/bin/python
################################################################################
# V36774
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
        return r"V-36774"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"A screen saver must be defined."

    def get_vulnerability_discussion(self):
        return r"Unattended systems are susceptible to unauthorized use and must be locked.  Specifying a screen saver ensures the screen saver timeout lock is initiated properly.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer. Set the policy value for User Configuration \ Administrative Templates \ Control Panel \ Personalization \ ''Force specific screen saver'' to ''Enabled'' with ''scrnsave.scr'' specified as the screen saver executable name."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', 'SCRNSAVE.EXE')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', ('SCRNSAVE.EXE=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "scrnsave.scr":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -name 'SCRNSAVE.EXE' -value scrnsave.scr")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.310(b),164.312(a)(2)(iii)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000374"
    
    def get_dod8500_2(self):
        return "PESL-1"

    def get_800_53(self):
        return "AC-11"
    
    def get_iso_27001(self):
        return "A.11.3.2, A.11.3.3, A.11.5.5"