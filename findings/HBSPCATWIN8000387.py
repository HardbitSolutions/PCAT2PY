
#!/usr/bin/python
################################################################################
# V36775
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD EQ finding
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
        return r"V-36775"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Changing the screen saver must be prevented."

    def get_vulnerability_discussion(self):
        return r"Unattended systems are susceptible to unauthorized use and must be locked.  Preventing users from changing the screen saver ensures an approved screen saver is used.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer. Set the policy value for User Configuration \ Administrative Templates \ Control Panel \ Personalization \ ''Prevent changing screen saver'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System', 'NoDispScrSavPage')

        # Output Lines
        self.__output = [r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System', ('NoDispScrSavPage=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -name 'NoDispScrSavPage' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.310(b),164.312(a)(2)(iii)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000387"
    
    def get_dod8500_2(self):
        return "PESL-1"

    def get_800_53(self):
        return "AC-11"
    
    def get_iso_27001(self):
        return "A.11.3.2, A.11.3.3, A.11.5.5"