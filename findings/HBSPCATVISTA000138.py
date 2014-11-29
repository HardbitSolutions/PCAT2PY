
#!/usr/bin/python
################################################################################
# V15698D
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
        return r"V-15698D"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Network ? Windows Connect Now Wireless Configuration"

    def get_vulnerability_discussion(self):
        return r"This check verifies that the configuration of wireless devices using Windows Connect Now is disabled. Set the policy value for Computer Configuration \ Administrative Templates \ Network \ Windows Connect Now ?Configuration of wireless settings using Windows Connect Now? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars', 'DisableWPDRegistrar')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars', ('DisableWPDRegistrar=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\WCN'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars' -name 'DisableWPDRegistrar' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000138"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"