
#!/usr/bin/python
################################################################################
# V15500
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
        return r"V-15500"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Third-party browser extensions must be disallowed."

    def get_vulnerability_discussion(self):
        return r"This policy setting allows you to manage whether Internet Explorer will launch COM add-ons, known as browser helper objects such as toolbars. Browser helper objects may contain flaws such as buffer overruns which impact Internet Explorer''s performance or stability. If you enable this policy setting, Internet Explorer automatically launches any browser helper objects that are installed on the user''s computer. If you disable this policy setting, browser helper objects do not launch. If you do not configure this policy, Internet Explorer automatically launches any browser helper objects that are installed on the user''s computer. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> ''Allow third-party browser extensions'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main', 'Enable Browser Extensions')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main', ('Enable Browser Extensions=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "no":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main' -name 'Enable Browser Extensions' -value no")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE10"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIETen000048"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"