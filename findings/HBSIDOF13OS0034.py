
#!/usr/bin/python
################################################################################
# V40860
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
        return r"V-40860"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The video informing a user about signing into Office365 must be disabled."

    def get_vulnerability_discussion(self):
        return r"Office 365 is a subscription-based service which offers access to various Microsoft Office applications.  Access to Office 365 will not be permitted; only locally installed and configured Office 2013 installations will be used. Since the ability to sign into Office 365 will be disabled, this policy, which determines whether a video about signing into Office365 is played when Office first runs, will also be disabled. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ First Run \ ''Disable First Run Movie'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\firstrun', 'disablemovie')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\firstrun', ('disablemovie=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\firstrun'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\firstrun' -name 'disablemovie' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0034"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"