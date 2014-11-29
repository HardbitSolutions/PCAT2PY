
#!/usr/bin/python
################################################################################
# V15580
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
        return r"V-15580"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Turn off page transitions is not enabled."

    def get_vulnerability_discussion(self):
        return r"This policy setting specifies if, as you move from one Web page to another, Internet Explorer fades out of the page you are leaving and fades into the page to which you are going.  If you enable this policy setting, page transitions will be turned off. The user cannot change this behavior.  If you disable this policy setting, page transitions will be turned on. The user cannot change this behavior.  If you do not configure this policy setting, the user can turn on or off page transitions. Manipulate the value: HKCU\Software\Policies\Microsoft\Internet Explorer\MainCriteria: Set the value Page_Transitions to REG_DWORD = 0."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main', 'Page_Transitions')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main', ('Page_Transitions=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main' -name 'Page_Transitions' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE7"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE7000108"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"