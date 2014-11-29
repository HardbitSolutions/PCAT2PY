
#!/usr/bin/python
################################################################################
# V16021
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
        return r"V-16021"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Windows Help Experience Improvement Program will be disabled"

    def get_vulnerability_discussion(self):
        return r"This check verifies that the Windows Help Experience Improvement Program is disabled to prevent information from being passed to the vendor. Set the policy value for User Configuration \ Administrative Templates \ System \ Internet Communication Management \ Internet Communication Settings \ ?Turn off Help Experience Improvement Program? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0', 'NoImplicitFeedback')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0', ('NoImplicitFeedback=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Assistance'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Assistance\Client'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0' -name 'NoImplicitFeedback' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000155"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"