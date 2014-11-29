
#!/usr/bin/python
################################################################################
# V15575
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
        return r"V-15575"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"External branding feature of Internet Explorer must be disallowed ."

    def get_vulnerability_discussion(self):
        return r"Prevents branding of Internet programs, such as customization of Internet Explorer and Outlook Express logos and title bars, by another party. If you enable this policy, it prevents customization of the browser by another party, such as an Internet service provider or Internet content provider. If you disable this policy or do not configure it, users could install customizations from another party-for example, when signing up for Internet services. This policy is intended for administrators who want to maintain a consistent browser across an organization. Manipulate the policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> ''Disable external branding of Internet Explorer'' to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Restrictions', 'NoExternalBranding')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Internet Explorer\Restrictions', ('NoExternalBranding=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Restrictions'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Restrictions' -name 'NoExternalBranding' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE9"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE9000101"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"