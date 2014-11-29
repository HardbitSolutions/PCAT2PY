
#!/usr/bin/python
################################################################################
# V16048
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
        return r"V-16048"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Windows Help Ratings feedback must be turned off."

    def get_vulnerability_discussion(self):
        return r"Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting ensures users cannot provide ratings feedback to Microsoft for Help content. Set the policy value for User Configuration \ Administrative Templates \ System \ Internet Communication Management \ Internet Communication Settings \ ''Turn off Help Ratings'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0', 'NoExplicitFeedback')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0', ('NoExplicitFeedback=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Assistance'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Assistance\Client'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0' -name 'NoExplicitFeedback' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000140"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"