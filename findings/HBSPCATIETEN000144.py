
#!/usr/bin/python
################################################################################
# V34456
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
        return r"V-34456"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Displaying of the reveal password button must be disallowed."

    def get_vulnerability_discussion(self):
        return r"This policy setting allows you to hide the reveal password button when Internet Explorer prompts users for a password. The reveal password button is displayed during password entry. When the user clicks the button, the current password value is visible until the mouse button is released (or until the tap ends). If you enable this policy setting, the reveal password button will be hidden for all password fields. Users and developers will not be able to depend on the reveal password button being displayed in any web form or web application. If you disable or do not configure this policy setting, the reveal password button can be shown by the application as a user types in a password. *Note: On at least Windows 8, if the ''Do not display the reveal password button'' policy setting located in Computer Configuration\Administrative Templates\Windows Components\Credential User Interface is enabled for the system, it will override this policy setting. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Security Features ''Do not display the reveal password button'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main', 'DisablePasswordReveal')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main', ('DisablePasswordReveal=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main' -name 'DisablePasswordReveal' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE10"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIETen000144"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"