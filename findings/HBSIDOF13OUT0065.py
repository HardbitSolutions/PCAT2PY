
#!/usr/bin/python
################################################################################
# V17808
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
        return r"V-17808"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"RSS Feeds must be disallowed."

    def get_vulnerability_discussion(self):
        return r"Users can subscribe to RSS feeds from within Outlook and read RSS items like email messages. If an organization has policies that govern the use of external resources such as RSS feeds, allowing users to subscribe to the RSS feed in Outlook will enable them to violate those policies. NOTE:If the use of RSS feeds integrated into Outlook is a mission need, and the network environment is configured with the following criteria: 1. Both the website issuing the RSS feeds and the Outlook email client must have an available network path to each other.2. Neither the website issuing the RSS feeds nor the Outlook email client has a network path to the public Internet.Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Account Settings \ RSS Feeds ''Turn off RSS feature'' to ''Enabled''.For all environments where the Outlook email clients have access to public Internet websites, RSS integration into Outlook is not permitted, and should be configured as follows:================================= Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Account Settings \ RSS Feeds ''Turn off RSS feature'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\rss', 'Enabled')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\rss', ('Enabled=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\rss'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\rss' -name 'Enabled' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Out0065"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"