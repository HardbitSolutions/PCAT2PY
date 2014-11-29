
#!/usr/bin/python
################################################################################
# V40882
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
        return r"V-40882"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The ability to run unsecure Office apps must be disabled."

    def get_vulnerability_discussion(self):
        return r"Unsecure apps for Office, which are apps that have web page or catalog locations that are not SSL-secured (https://), and/or are not in users'' Internet zones may allow data to be transmitted/accessed via clear text to outside sources. By configuring this policy to be disabled, users will be prevented from transmitting/accessing data in a nonsecure manner. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Security Settings \ Trust Center \ Trusted Catalogs ''Allow Unsecure Apps and Catalogs'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\wef\trustedcatalogs', 'requireserververification')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\wef\trustedcatalogs', ('requireserververification=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\wef'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\wef\trustedcatalogs'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\wef\trustedcatalogs' -name 'requireserververification' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0043"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"