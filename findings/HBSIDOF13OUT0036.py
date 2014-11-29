
#!/usr/bin/python
################################################################################
# V17678
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
        return r"V-17678"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Internet calendar integration in Outlook must be disabled."

    def get_vulnerability_discussion(self):
        return r"The Internet Calendar feature in Outlook enables users to publish calendars online (using the webcal:// protocol) and subscribe to calendars that others have published. When users subscribe to an Internet calendar, Outlook queries the calendar at regular intervals and downloads any changes as they are posted.By default, Outlook allows users to subscribe to Internet calendars. When an organization has policies that govern the use of external resources such as Internet calendars, this feature will enable users to violate those policies. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Account Settings \ Internet Calendars ''Do not include Internet Calendar integration in Outlook'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\webcal', 'Disable')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\webcal', ('Disable=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\webcal'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\webcal' -name 'Disable' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Out0036"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"