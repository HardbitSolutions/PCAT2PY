
#!/usr/bin/python
################################################################################
# V1165
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
        return r"V-1165"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The computer account password is prevented from being reset."

    def get_vulnerability_discussion(self):
        return r"As a part of Windows security, computer account passwords are changed automatically.  Enabling this policy to disable automatic password changes can make the system more vulnerable to malicious access.  Frequent password changes can be a significant safeguard for your system.  If this policy is disabled, a new password for the computer account will be generated every week. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Domain Member: Disable Machine Account Password Changes? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters', 'DisablePasswordChange')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters', ('DisablePasswordChange=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Netlogon'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -name 'DisablePasswordChange' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(D)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000067"
    
    def get_dod8500_2(self):
        return "IAIA-1, IAIA-2"

    def get_800_53(self):
        return "IA-2, IA-4(2), IA-4(3), IA-5, IA-5(1), IA-5(3), IA-5(5), IA-5(6), IA-5(7)"
    
    def get_iso_27001(self):
        return "A.10.9.1, A.10.9.2, A.11.4.2, A.11.5.1, A.11.5.2 ,A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.3"