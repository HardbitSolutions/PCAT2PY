#!/usr/bin/python
################################################################################
# V21954
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD NE finding
#
# 09/21/2014 Original Construction
# 10/03/2014 Fixed condition statement in check method
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
        return r"V-21954"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Kerberos encryption types must be configured to prevent the use of DES encryption suites."

    def get_vulnerability_discussion(self):
        return r"Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type for Kerberos, preventing the use of the DES encryption suites. The default configuration supports this requirement.  If Kerberos encryption types must be configured, ensure that the following are not selected:DES_CBC_CRCDES_CBC_MD5If the policy for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''Network security: Configure encryption types allowed for Kerberos'' is configured, only the following selections are allowed:RC4_HMAC_MD5AES128_HMAC_SHA1AES256_HMAC_SHA1Future encryption types"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters', 'SupportedEncryptionTypes')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters', ('SupportedEncryptionTypes=' + str(dword))]

        if self.__verbose:
            print self.__output

        if not (dword >= 1 or dword <= 3):
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -name 'SupportedEncryptionTypes' -value Not Equal 1 to 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000175"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"