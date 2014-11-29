
#!/usr/bin/python
################################################################################
# V34590
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
        return r"V-34590"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"URL Suggestions must be disallowed."

    def get_vulnerability_discussion(self):
        return r"This policy setting turns off URL Suggestions. URL Suggestions allow users to auto complete URLs in the address bar based on common URLs. The list of common URLs is stored locally and is updated once a month. No user data is sent over the internet by this feature. If you enable this policy setting, URL Suggestions will be turned off. Users will not be able to turn on URL Suggestions. If you disable this policy setting, URL Suggestions will be turned on. Users will not be able to turn off URL Suggestions. If you do not configure this policy setting, URL Suggestions will be turned on. Users will be able to turn on or turn off URL Suggestions in the Internet Options dialog. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Settings-> AutoComplete ''Turn off URL Suggestions'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\DomainSuggestion', 'Enabled')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\DomainSuggestion', ('Enabled=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\DomainSuggestion'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\DomainSuggestion' -name 'Enabled' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE10"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIETen000143"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"