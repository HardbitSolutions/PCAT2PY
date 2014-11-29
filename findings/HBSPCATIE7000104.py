
#!/usr/bin/python
################################################################################
# V15574B
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
        return r"V-15574B"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable AutoComplete for forms is not enabled."

    def get_vulnerability_discussion(self):
        return r"This AutoComplete feature suggests possible matches when users are filling up forms.  If you enable this setting, the user is not suggested matches when filling forms. The user cannot change it.  If you disable this setting, the user is suggested possible matches when filling forms. The user cannot change it.If you do not configure this setting, the user has the freedom to turn on the auto-complete feature for forms.  To display this option, the users open the Internet Options dialog box, click the Contents Tab and click the Settings button. Manipulate the value: HKCU\Software\Policies\Microsoft\Internet Explorer\MainCriteria: Set the value Use FormSuggest to REG_SZ = no.HKCU\Software\Policies\Microsoft\Internet Explorer\Control PanelCriteria: Set the value FormSuggest to REG_DWORD = 1."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel', 'FormSuggest')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel', ('FormSuggest=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKCU:\HKCU:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKCU:\HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel' -name 'FormSuggest' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE7"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE7000104"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"