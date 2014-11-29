
#!/usr/bin/python
################################################################################
# V40886
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
        return r"V-40886"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Office Telemetry Agent must be configured to obfuscate the file name, file path, and title of Office documents before uploading telemetry data to the shared folder."

    def get_vulnerability_discussion(self):
        return r"This policy setting configures the Office Telemetry Agent to disguise, or obfuscate, certain file properties that are reported in telemetry data. If this policy setting is enabled, Office Telemetry Agent obfuscates the file name, file path, and title of Office documents before uploading telemetry data to the shared folder. If this policy setting is disabled or not configured, the Office Telemetry Agent uploads telemetry data that shows the full file name, file path, and title of all Office documents. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Telemetry Dashboard \ ''Turn on privacy setting in Office Telemetry Agent'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\osm', 'enablefileobfuscation')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\osm', ('enablefileobfuscation=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\osm'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\osm' -name 'enablefileobfuscation' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0047"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"