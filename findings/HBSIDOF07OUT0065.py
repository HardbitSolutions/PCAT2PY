
#!/usr/bin/python
################################################################################
# V17791
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
        return r"V-17791"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Configure S/Mime password setting - default S/Mime password time"

    def get_vulnerability_discussion(self):
        return r"Key Management Server (KMS) was a product that could be integrated with certain versions of Microsoft Exchange Server prior to Exchange 2000 SP2. Users must supply a password to use certificates issued by KMS to sign or decrypt e-mail messages. When Outlook 2007 prompts users for the correct password, they can specify a length of time in minutes for Outlook to cache the password. Users will not be prompted to continually reenter the password during the specified time period. By default, Outlook remembers KMS passwords for 30 minutes, which users can change to any number of minutes up to 300. The longer the period of time a user specifies, the greater the chance that an unauthorized person can use the user''s computer to access sensitive information. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Outlook 2007 \ Security \ Cryptography ?S/MIME password settings? will be set to ?Enabled? and Default S/MIME password time will be set to 30."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Cryptography\Defaults\Provider\ Microsoft Exchange Cryptographic Provider v1.0', 'DefPwdTime')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Cryptography\Defaults\Provider\ Microsoft Exchange Cryptographic Provider v1.0', ('DefPwdTime=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 30:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Cryptography\Defaults'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Cryptography\Defaults\Provider'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Cryptography\Defaults\Provider\ Microsoft Exchange Cryptographic Provider v1.0'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Cryptography\Defaults\Provider\ Microsoft Exchange Cryptographic Provider v1.0' -name 'DefPwdTime' -value 30 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Out0065"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"