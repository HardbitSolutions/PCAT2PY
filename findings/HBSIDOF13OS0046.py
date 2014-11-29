
#!/usr/bin/python
################################################################################
# V40885
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
        return r"V-40885"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The ability of the Office Telemetry Agent to periodically upload telemetry data to a shared folder must be disabled."

    def get_vulnerability_discussion(self):
        return r"Office Telemetry is a new compatibility monitoring framework. When an Office document or solution is loaded, used, closed, or raises an error in certain Office 2013 applications, the Office Telemetry application adds a record about the event to a local data store. Each record includes a description of the problem and a link to more information. Inventory and usage data is also tracked. The actual logging capability will be enabled, but this policy allows that data to be uploaded to a remote location which, if enabled, could pass information about the internal network and configuration to that remote site. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Telemetry Dashboard \ ''Turn on data uploading for Office Telemetry Agent'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\osm', 'enableupload')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\osm', ('enableupload=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\osm'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\osm' -name 'enableupload' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0046"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"