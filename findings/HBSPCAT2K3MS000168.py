
#!/usr/bin/python
################################################################################
# V4444
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
        return r"V-4444"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Users are not required to enter a password to access private keys."

    def get_vulnerability_discussion(self):
        return r"Configuring this setting so that users must provide a password (distinct from their domain password) every time they use a key makes it more difficult for an attacker to access locally stored user keys, even if the attacker takes control of the users computer and determines their logon password. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?System cryptography: Force strong key protection for user keys stored in the computer? to ?User must enter a password each time they use a key?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Cryptography', 'ForceKeyProtection')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Cryptography', ('ForceKeyProtection=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Cryptography'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Cryptography' -name 'ForceKeyProtection' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(D)"
    
    def get_pci(self):
        return "8.2"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000168"
    
    def get_dod8500_2(self):
        return "IAIA-1, IAIA-2"

    def get_800_53(self):
        return "IA-2, IA-4(2), IA-4(3), IA-5, IA-5(1), IA-5(3), IA-5(5), IA-5(6), IA-5(7)"
    
    def get_iso_27001(self):
        return "A.10.9.1, A.10.9.2, A.11.4.2, A.11.5.1, A.11.5.2 ,A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.3"