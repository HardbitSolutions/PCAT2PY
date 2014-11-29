
#!/usr/bin/python
################################################################################
# V40859
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
        return r"V-40859"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Enable Updates and Disable Updates options in the UI must be hidden from users."

    def get_vulnerability_discussion(self):
        return r"This policy setting allows the user interface (UI) options to enable or disable Office automatic updates to be hidden from users. These options are found in the Product Information area of all Office applications installed via Click-to-Run. This policy setting has no effect on Office applications installed via Windows Installer. If this policy setting is enabled, the ''Enable Updates'' and ''Disable Updates'' options in the UI are hidden from users. If this policy setting is not configured, the ''Enable Updates'' and ''Disable Updates'' options are visible, and users can enable or disable Office automatic updates from the UI. Set the policy value for: Computer Configuration \ Administrative Templates \ Microsoft Office 2013 (Machine)\Updates\''Hide option to enable or disable updates''  is set to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate', 'HideEnableDisableUpdates')

        # Output Lines
        self.__output = [r'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate', ('HideEnableDisableUpdates=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKLM:\software\policies\Microsoft\office\15.0\common'")
        cli.powershell(r"New-Item -path 'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\software\policies\Microsoft\office\15.0\common\officeupdate' -name 'HideEnableDisableUpdates' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0033"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"