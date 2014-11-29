
#!/usr/bin/python
################################################################################
# V36691
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD LE finding
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-36691"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The display must turn off after 20 minutes of inactivity when the system is plugged in."

    def get_vulnerability_discussion(self):
        return r"Turning off an inactive display supports energy saving initiatives. Set the policy value for Computer Configuration \ Administrative Templates \ System \ Power Management \ Video and Display Settings \ ''Turn Off the Display (Plugged In)'' to ''Enabled'' with ''1200'' seconds or less."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E', 'ACSettingIndex')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E', ('ACSettingIndex=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword <= 1200:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Power'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E' -name 'ACSettingIndex' -value 1200 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000318"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"