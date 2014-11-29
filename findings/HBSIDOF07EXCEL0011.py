
#!/usr/bin/python
################################################################################
# V17518
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
        return r"V-17518"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Block opening of ''open XML'' format files created by pre-release versions of Excel."

    def get_vulnerability_discussion(self):
        return r"By default, users can open files that were saved in pre-release versions of the new Office Open XML format, which underwent some minor changes prior to the final release of Office 2007. Excel Open XML files usually have the following extensions:?	.xlsb?	.xlsx?	.xlsm?	.xltx?	.xltm?	.xlamIf a vulnerability is discovered that affects these kinds of files, you can use this setting to protect your organization against attacks by temporarily preventing users from opening files in these formats until a security patch is available.By default, these file types are not blocked in Office 2007 products. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Excel 2007 \ Block file formats \ Open ?Block opening of files created by pre-release versions of Excel 2007? will be set to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock', 'Excel12BetaFiles')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock', ('Excel12BetaFiles=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileOpenBlock' -name 'Excel12BetaFiles' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Excel0011"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"