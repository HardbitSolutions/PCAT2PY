
#!/usr/bin/python
################################################################################
# V1085
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1085"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Floppy media devices are not allocated upon user logon."

    def get_vulnerability_discussion(self):
        return r"This check verifies that Windows is configured to not limit access to floppy drives when a user is logged on locally. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Devices: Restrict floppy access to locally logged-on user only? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Allocatefloppies')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', ('Allocatefloppies=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "0":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'Allocatefloppies' -value 0")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win7"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCATWIN7000013"
    
    def get_dod8500_2(self):
        return "ECLP-1, ECSC-1"

    def get_800_53(self):
        return "AC-6, CM-6"
    
    def get_iso_27001(self):
        return "A.11.2.2, A.11.4.1, A.11.4.4, A.11.5.4, A.11.6.1, A.12.4.3, A.10.10.2"