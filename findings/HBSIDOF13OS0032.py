
#!/usr/bin/python
################################################################################
# V40858
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
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-40858"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Office automatic updates must be enabled for Office products installed via Click-to-Run and configured to use a Trusted site."

    def get_vulnerability_discussion(self):
        return r"This policy setting controls whether the Office automatic updates are enabled or disabled for all Office products installed via Click-to-Run. This policy has no effect on Office products installed via Windows Installer. If this policy setting is enabled, Office periodically checks for updates. When updates are detected, Office downloads and applies them in the background. If policy setting is disabled, Office will not check for updates. Without receiving automatic updates, vulnerabilities found within the Office products will not be applied, leaving the vulnerabilities exposed. Set the policy value for: Computer Configuration \ Administrative Templates \ Microsoft Office 2013 (Machine)\Updates\''Enable Automatic Updates'' to ''Enabled''.Set the policy value for: Computer Configuration \ Administrative Templates \ Windows Components \ Windows Updates \ ''Specify intranet Microsoft update service location''  to ''Enabled'' and the ''Set the intranet update service for detecting updates:'' and the ''Set the intranet statistics server:''to point to an Intranet system."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate', 'EnableAutomaticUpdates')

        # Output Lines
        self.__output = [r'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate', ('EnableAutomaticUpdates=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKLM:\software\policies\Microsoft\office\15.0\common'")
        cli.powershell(r"New-Item -path 'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate' -name 'EnableAutomaticUpdates' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0032"
    
    def get_dod8500_2(self):
        return ""

    def get_800_53(self):
        return "SI-2"
    
    def get_iso_27001(self):
        return "A.12.6.1, A.13.1.2"