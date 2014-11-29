
#!/usr/bin/python
################################################################################
# V26625
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
        return r"V-26625"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Publisher 2013 application must be prevented from loading any custom user"

    def get_vulnerability_discussion(self):
        return r"This policy setting controls whether Office 2013 applications load any custom user interface (UI) code included with a document or template.  Office 2013 allows developers to extend the UI with customization code that is included in a document or template. If this policy setting is enabled, Office 2013 applications cannot load any UI customization code included with documents and templates. If this policy setting is disabled or not configured, Office 2013 applications load any UI customization code included with a document or template when opening it, leaving the Office 2013 application susceptible to malicious code. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Global Options \ Customize \ ''Disable UI extending from documents and templates'' to ''Enabled''. Select the policy option for ''Disallow in Publisher''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\common\toolbars\publisher', 'NoExtensibilityCustomizationFromDocument')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\common\toolbars\publisher', ('NoExtensibilityCustomizationFromDocument=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\common\toolbars'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\common\toolbars\publisher'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\common\toolbars\publisher' -name 'NoExtensibilityCustomizationFromDocument' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Publisher"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Pub0010"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"