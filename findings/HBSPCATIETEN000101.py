
#!/usr/bin/python
################################################################################
# V14245
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
        return r"V-14245"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Ability for users to enable or disable add-ons must be enforced."

    def get_vulnerability_discussion(self):
        return r"Users often choose to install add-ons that are not permitted by an organization''s security policy. Such add-ons can pose a significant security and privacy risk to your network. This policy setting allows you to manage whether users have the ability to allow or deny add-ons through Add-On Manager. If you enable this policy setting, users cannot enable or disable add-ons through Add-On Manager. The only exception occurs if an add-on has been specifically entered into the ''Add-On List'' policy setting in such a way as to allow users to continue to manage the add-on. In this case, the user can still manage the add-on. If you disable or do not configure this policy setting, the appropriate controls in the Add-On Manager will be available to the user. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> ''Do Not Allow users to enable or disable add-ons'' to ''Disabled'' or ''Not Configured''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions', 'NoExtensionManagement')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions', ('NoExtensionManagement=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions' -name 'NoExtensionManagement' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE10"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIETen000101"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"