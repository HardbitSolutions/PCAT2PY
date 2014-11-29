
#!/usr/bin/python
################################################################################
# V17619
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
        return r"V-17619"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Encryption type for password protected Open XML files - Office"

    def get_vulnerability_discussion(self):
        return r"If unencrypted files are intercepted, sensitive information in the files can be compromised. To protect information confidentiality, 2007 Office application files can be encrypted and password protected. Only users who know the correct password will be able to decrypt such files.On computers that run Windows Vista, the default cryptographic service provider (CSP) is Microsoft Enhanced RSA and AES Cryptographic Provider, AES-128, 128-bit. On computers that run Windows XP, the default CSP is Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype), AES-128, 128-bit. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2007 system \ Security Settings ?Encryption type for password protected Office Open XML files? will be set to ?Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 128,128)? for NON XP OS''s or ?Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype),AES 128,128)? for XP OS. NOTE: ?Microsoft Enhanced RSA and AES Cryptographic Provider,AES 128,128'' is minimum setting required where can be up to key length of 256 if environment will support as ?Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)? or ?Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype),AES 256,256)?"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Security', 'OpenXMLEncryption')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Security', ('OpenXMLEncryption=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 128,128":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Security' -name 'OpenXMLEncryption' -value Microsoft Enhanced RSA and AES Cryptographic Provider,AES 128,128")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07OS0012"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"