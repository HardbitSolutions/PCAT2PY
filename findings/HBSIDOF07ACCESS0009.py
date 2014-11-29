
#!/usr/bin/python
################################################################################
# V17584
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
        return r"V-17584"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Set the default saved file format for Access."

    def get_vulnerability_discussion(self):
        return r"By default, when users create new database files, Access 2007 saves them in the new Access 2007 format. Users can change this functionality by clicking the Office button, clicking Access Options, and then selecting a file format from the Default file format list.If a new database is created in an inappropriate format, some users might be unable to open or use it. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Access 2007 \ Miscellaneous ?Default File Format? will be set to ?Enabled (Access 2007)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Settings', 'Default File Format')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Settings', ('Default File Format=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 12:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Settings'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Settings' -name 'Default File Format' -value 12 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Access"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Access0009"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"