
#!/usr/bin/python
################################################################################
# V26630
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
        return r"V-26630"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Online content options must be configured for offline content availability."

    def get_vulnerability_discussion(self):
        return r"The Office 2010 Help system automatically searches Microsoft Office.com for content when a computer is connected to the Internet.  Users can change this default by clearing the Search Microsoft Office.com for Help content when I''m connected to the Internet check box in the Privacy Options section of the Trust Center.  If your organization has policies that govern the use of external resources such as Office.com, allowing the Help system to download content might cause users to violate these policies. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2010 \ Tools | Options | General | Service Options... \ Online Content  ?Online content options? to ?Enabled: Search only offline content whenever available?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet', 'UseOnlineContent')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet', ('UseOnlineContent=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet' -name 'UseOnlineContent' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OS0036"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"