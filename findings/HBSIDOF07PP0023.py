
#!/usr/bin/python
################################################################################
# V17563
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
        return r"V-17563"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Block PowerPoint from automatically opening converters to view older PowerPoint presentations."

    def get_vulnerability_discussion(self):
        return r"PowerPoint 2007 requires the use of a conversion tool to open presentations saved in versions of PowerPoint older than PowerPoint 97, such as PowerPoint 95, PowerPoint 4.0, and others.If a vulnerability is discovered that affects these kinds of files, you can use this setting to protect your organization against attacks by temporarily preventing users from opening files in these formats until a security patch is available. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office PowerPoint 2007 \ Block file formats \ Open ?Block opening of Converters? will be set to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security\FileOpenBlock', 'Converters')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security\FileOpenBlock', ('Converters=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security\FileOpenBlock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security\FileOpenBlock' -name 'Converters' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07PP0023"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"