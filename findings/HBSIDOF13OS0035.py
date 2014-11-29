
#!/usr/bin/python
################################################################################
# V40861
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
        return r"V-40861"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The first-run prompt to sign into Office365 must be disabled."

    def get_vulnerability_discussion(self):
        return r"Office 365 functionality allows users to provide credentials for accessing Office 365 using either their Microsoft Account, or the user ID assigned by the organization. Access to Office 365 will not be permitted; only locally installed and configured Office 2013 installations will be used. Since the ability to sign into Office 365 will be disabled, this policy, which determines whether the Office First Run comes up on first application boot if not previously viewed, will also be disabled. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ First Run  \ ''Disable Office First Run on application boot'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\firstrun', 'bootedrtm')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\firstrun', ('bootedrtm=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\firstrun'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\firstrun' -name 'bootedrtm' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0035"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"