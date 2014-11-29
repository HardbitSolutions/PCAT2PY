
#!/usr/bin/python
################################################################################
# V30776
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
        return r"V-30776"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Suggested Sites functionality must be disallowed."

    def get_vulnerability_discussion(self):
        return r"This policy setting controls the Suggested Sites feature, which recommends sites based on the user''s browsing activity. Suggested Sites reports a user''s browsing history to Microsoft to store and monitor user page activity to suggest sites the user might want to visit. If you enable this policy setting, the user will not be prompted to enable the Suggested Sites and the user''s browsing activities will be sent and stored online to produce suggestions. If you disable this policy setting, the entry points and functionality associated with this feature will be disabled. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> ''Turn on Suggested Sites'' to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites', 'Enabled')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites', ('Enabled=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites' -name 'Enabled' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE9"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE9000110"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"