
#!/usr/bin/python
################################################################################
# V15582
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
        return r"V-15582"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Turn on the Internet Connection Wizard Auto Detect is not disabled."

    def get_vulnerability_discussion(self):
        return r"This policy setting determines if the Internet Connection Wizard was completed. If it was not completed, it launches the Internet Connection Wizard.  If you enable this policy setting, the Internet Connection Wizard is launched automatically if it was not completed before. The user cannot prevent the wizard from launching.  If you disable this policy setting, the Internet Connection Wizard is not launched automatically. The user can launch the wizard manually.  If you do not configure this policy setting, the user will have the freedom to decide whether the Internet Connection Wizard should be launched automatically. Manipulate the value: HKCU\Software\Policies\Microsoft\Internet Connection WizardCriteria: Set the value DisableICW to REG_DWORD = 1."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Internet Connection Wizard', 'DisableICW')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Internet Connection Wizard', ('DisableICW=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Internet Connection Wizard'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Internet Connection Wizard' -name 'DisableICW' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE7"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE7000111"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"