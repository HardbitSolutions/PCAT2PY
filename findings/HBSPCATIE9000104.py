
#!/usr/bin/python
################################################################################
# V15581B
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SZ EQ finding
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
        return r"V-15581B"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"AutoComplete feature for user names and passwords on forms must be disallowed."

    def get_vulnerability_discussion(self):
        return r"It is possible this feature will cache sensitive data and store it in the user''s profile where it might not be protected as rigorously as required by organizational policy. This policy setting controls automatic completion of fields in forms on web pages. If you enable this setting, the user cannot change ''User name and passwords on forms'' or ''prompt me to save passwords''. The Auto Complete feature for user names and passwords on forms will be turned on. If you disable this setting, the user cannot change ''User name and passwords on forms'' or ''prompt me to save passwords''. The Auto Complete feature for user names and passwords on forms is turned off. The user also cannot opt to be prompted to save passwords. If you do not configure this setting, the user has the freedom of turning on Auto Complete for user name and passwords on forms, and the option of prompting to save passwords. Manipulate the policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> ''Turn on the auto-complete feature for user names and passwords on forms'' to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main', 'FormSuggest PW Ask')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main', ('FormSuggest PW Ask=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "no":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -name 'FormSuggest PW Ask' -value no")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE9"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE9000104"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"