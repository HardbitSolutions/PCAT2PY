
#!/usr/bin/python
################################################################################
# V17776
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
        return r"V-17776"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Level of calendar details that a user can publish must be restricted."

    def get_vulnerability_discussion(self):
        return r"Outlook users can share their calendars with selected others by publishing them to the Microsoft Office Outlook Calendar Sharing Service. Users can choose from three levels of detail:?	Availability only. Authorized visitors will see the user''s time marked as Free, Busy, tentative, or Out of Office, but will not be able to see the subjects or details of calendar items.?	Limited details. Authorized visitors can see the user''s availability and the subjects of calendar items only. They will not be able to view the details of calendar items. Optionally, users can allow visitors to see the existence of private items.?	Full details. Authorized visitors can see the full details of calendar items. Optionally, users can allow visitors to see the existence of private items and to access attachments within calendar items.If users are allowed to publish limited or full details, sensitive information in their calendars could become exposed to parties who are not authorized to have that information. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2010 \ Outlook Options \ Preferences \ Calendar Options \ Office.com Sharing Service ?Restrict level of calendar details users can publish? to ?Enabled (Disables ?Full details? and ?Limited details?)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\outlook\options\pubcal', 'PublishCalendarDetailsPolicy')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\outlook\options\pubcal', ('PublishCalendarDetailsPolicy=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 16384:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\outlook\options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\outlook\options\pubcal'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\outlook\options\pubcal' -name 'PublishCalendarDetailsPolicy' -value 16384 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OUT0055"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"