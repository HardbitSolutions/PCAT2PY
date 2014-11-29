
#!/usr/bin/python
################################################################################
# V36657
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
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-36657"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The screen saver must be password protected."

    def get_vulnerability_discussion(self):
        return r"Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer. Set the policy value for User Configuration \ Administrative Templates \ Control Panel \ Personalization \ ''Password protect the screen saver'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', 'ScreenSaverIsSecure')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', ('ScreenSaverIsSecure=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "1":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -name 'ScreenSaverIsSecure' -value 1")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.310(b),164.312(a)(2)(iii)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000319"
    
    def get_dod8500_2(self):
        return "PESL-1"

    def get_800_53(self):
        return "AC-11"
    
    def get_iso_27001(self):
        return "A.11.3.2, A.11.3.3, A.11.5.5"