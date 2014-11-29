
#!/usr/bin/python
################################################################################
# V15497
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
        return r"V-15497"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Allow active content from CDs to run on user machines is not disabled."

    def get_vulnerability_discussion(self):
        return r"This policy setting allows you to manage whether users receive a dialog requesting permission for active content on a CD to run.  If you enable this policy setting, active content on a CD will run without a prompt.If you disable this policy setting, active content on a CD will always prompt before running.  If you do not configure this policy, users can choose whether to be prompted before running active content on a CD. Manipulate the value: HKLM\Software\Policies\Microsoft\Internet  Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\SettingsCriteria: Set the value LOCALMACHINE_CD_UNLOCK to REG_DWORD = 0."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet  Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings', 'LOCALMACHINE_CD_UNLOCK')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet  Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings', ('LOCALMACHINE_CD_UNLOCK=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet  Explorer\Main\FeatureControl'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet  Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet  Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet  Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings' -name 'LOCALMACHINE_CD_UNLOCK' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE7"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE7000050"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"