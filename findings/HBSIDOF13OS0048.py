
#!/usr/bin/python
################################################################################
# V40887
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
        return r"V-40887"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The  Office Telemetry Agent and Office applications must be configured to collect telemetry data."

    def get_vulnerability_discussion(self):
        return r"Office Telemetry is a new compatibility monitoring framework. When an Office document or solution is loaded, used, closed, or raises an error in certain Office 2013 applications, the Office Telemetry application adds a record about the event to a local data store. Each record includes a description of the problem and a link to more information. Inventory and usage data is also tracked. This policy setting allows the data collection features in Office that are used by the Office Telemetry Dashboard and Office Telemetry Log to be turned on. If this policy setting is enabled, Office Telemetry Agent and Office applications will collect telemetry data, which includes Office application usage, most recently used Office documents (including file names) and solutions usage, compatibility issues, and critical errors that occur on the local computers. Office Telemetry Dashboard can be used to view this data remotely, and users can use Office Telemetry Log to view this data on their local computers. If this policy setting is disabled or not configured, the Office Telemetry Agent and Office applications do not generate or collect telemetry data. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Telemetry Dashboard \ ''Turn on telemetry data collection'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\osm', 'enablelogging')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\osm', ('enablelogging=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\osm'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\osm' -name 'enablelogging' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0048"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"