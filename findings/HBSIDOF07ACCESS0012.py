
#!/usr/bin/python
################################################################################
# V17810
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
        return r"V-17810"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Enable the feature to underline hyperlinks in Access."

    def get_vulnerability_discussion(self):
        return r"By default, Access 2007 underlines hyperlinks that appear in tables, queries, forms, and reports. If this configuration is changed, users might click on dangerous hyperlinks without realizing it, which could pose a security risk Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Access 2007 \ Application Settings \ Web Options \ General ?Underline Hyperlinks? will be set to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Internet', 'DoNotUnderlineHyperlinks')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Internet', ('DoNotUnderlineHyperlinks=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Internet'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Internet' -name 'DoNotUnderlineHyperlinks' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Access"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Access0012"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"