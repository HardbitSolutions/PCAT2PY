
#!/usr/bin/python
################################################################################
# V41492
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
        return r"V-41492"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The use of the weather bar in Outlook must be disabled"

    def get_vulnerability_discussion(self):
        return r"The Weather Bar in Outlook displays weather conditions and forecast for a geographic location. By default, Outlook uses weather data provided by MSN Weather. The Weather Bar supports third-party weather data web services that follow a defined protocol to communicate with Outlook. As long as a third-party weather data service supports this protocol, users can choose that weather data service to provide weather data in the Weather Bar. Since the Weather Bar communicates to external, commercial weather sites, enabling it introduces the possibility of connections to malicious sites that could download malware into the environment. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Outlook Options \ Preferences \ Calendar Options \ ''Disable Weather Bar'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\calendar', 'disableweather')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\calendar', ('disableweather=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook\options'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\calendar'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\calendar' -name 'disableweather' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Out0081"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"