
#!/usr/bin/python
################################################################################
# V17617
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
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-17617"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The encryption type for password protected Office 97 thru Office 2003 must be set."

    def get_vulnerability_discussion(self):
        return r"If unencrypted files are intercepted, sensitive information in the files can be compromised. To protect information confidentiality, Microsoft Office application files can be encrypted and password protected. Only users who know the correct password will be able to decrypt such files. Since some encryption types are less secure and easier to breach, Microsoft Enhanced RSA and AES Cryptographic Provider, AES-256, 256-bit should be used when encrypting documents. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Security Settings ''Encryption type for password protected Office 97-2003 files'' to ''Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider, AES-256, 256-bit)''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKCU:\Software\Policies\Microsoft\Office\15.0\common\security', 'DefaultEncryption12')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\common\security', ('DefaultEncryption12=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "Microsoft Enhanced RSA and AES Cryptographic Provider,AES-256,256-bit":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common\security' -name 'DefaultEncryption12' -value Microsoft Enhanced RSA and AES Cryptographic Provider,AES-256,256-bit")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0009"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"