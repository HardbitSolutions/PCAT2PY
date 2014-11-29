
#!/usr/bin/python
################################################################################
# V26615
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
        return r"V-26615"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Files in unsafe locations must be opened in Protected View."

    def get_vulnerability_discussion(self):
        return r"This policy setting determines if files located in unsafe locations will open in Protected View. If unsafe locations have not been specified, only the ''Downloaded Program Files'' and ''Temporary Internet Files'' folders are considered unsafe locations. If enabling this policy setting, files located in unsafe locations do not open in Protected View. If disabling or not configuring this policy setting, files located in unsafe locations open in Protected View. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Word 2013 \ Word Options \ Security \ Trust Center \ Protected View ''Do not open files in unsafe locations in Protected View'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\protectedview', 'DisableUnsafeLocationsInPV')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\protectedview', ('DisableUnsafeLocationsInPV=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\protectedview'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\protectedview' -name 'DisableUnsafeLocationsInPV' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Word"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Word0024"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"