
#!/usr/bin/python
################################################################################
# V17519
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
        return r"V-17519"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Block Opening of ''Open XML'' file types to prevent them automatically executing code."

    def get_vulnerability_discussion(self):
        return r"The Office Open XML format file types introduced in the 2007 Microsoft Office release offer a number of benefits compared to the previous binary file types supported in Office 2003, including the potential to reduce the effects of malicious code. Files can be identified as unable to run code, and will therefore ignore any embedded code. Also, any files that do have embedded code are easier to identify. If a vulnerability is discovered that affects Office Open XML files, you can use this setting to protect your organization against attacks by temporarily preventing users from opening files in these formats until a security patch is available. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Excel 2007 \ Block file formats \ Open ?Block opening of Open XML file types? will be set to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock', 'OpenXmlFiles')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock', ('OpenXmlFiles=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock' -name 'OpenXmlFiles' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Excel0012"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"