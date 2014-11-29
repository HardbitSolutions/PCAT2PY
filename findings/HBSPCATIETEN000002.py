
#!/usr/bin/python
################################################################################
# V17296
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
        return r"V-17296"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"First Run Wizard settings must be established for a home page."

    def get_vulnerability_discussion(self):
        return r"This policy setting prevents Internet Explorer from running the First Run Wizard the first time a user starts the browser after installing Internet Explorer or Windows. If this policy setting is enabled, IE is configurable in two ways: 1) Skip the First Run Wizard, and go directly to the user''s home page, or 2) Skip the First Run Wizard, and go directly to the ''Welcome to Internet Explorer'' web page. If this policy setting is disabled or not configured, Internet Explorer may run the First Run Wizard the first time the browser is started after installation and provide users the ability to configure IE outside of environment policy. Starting with Windows 8, the ''Welcome to Internet Explorer'' web page is not available. The user''s home page will display regardless of which option is chosen. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> ''Prevent running First Run Wizard'' to ''Enabled'', and select ''Go directly to home page'' from the drop-down box."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main', 'DisableFirstRunCustomize')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main', ('DisableFirstRunCustomize=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main' -name 'DisableFirstRunCustomize' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE10"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIETen000002"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"