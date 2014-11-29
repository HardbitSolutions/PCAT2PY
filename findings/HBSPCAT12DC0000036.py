
#!/usr/bin/python
################################################################################
# V1151
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1151"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The print driver installation privilege must be restricted to administrators."

    def get_vulnerability_discussion(self):
        return r"Allowing users to install drivers can introduce malware or cause the instability of a system.  This capability should be restricted to administrators. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''Devices: Prevent users from installing printer drivers'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers', 'AddPrinterDrivers')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers', ('AddPrinterDrivers=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Print\Providers'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -name 'AddPrinterDrivers' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000036"
    
    def get_dod8500_2(self):
        return "ECLP-1"

    def get_800_53(self):
        return "AC-5, AC-6, AC-6(2)"
    
    def get_iso_27001(self):
        return "A.10.1.3, A.11.2.2, A.11.4.1, A.11.4.4, A.11.5.4, A.11.6.1, A.12.4.3"