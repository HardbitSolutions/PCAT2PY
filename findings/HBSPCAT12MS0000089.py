
#!/usr/bin/python
################################################################################
# V15672
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-15672"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Event Viewer Events.asp links must be turned off."

    def get_vulnerability_discussion(self):
        return r"Viewing events is a function of administrators, who must not access the internet with privileged accounts.  This setting will disable  Events.asp hyperlinks in Event Viewer to prevent links to the internet from within events. Set the policy value for Computer Configuration \ Administrative Templates \ System \ Internet Communication Management \ Internet Communication settings \ ''Turn off Event Viewer ''Events.asp'' links'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\EventViewer', 'MicrosoftEventVwrDisableLinks')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\EventViewer', ('MicrosoftEventVwrDisableLinks=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\EventViewer'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\EventViewer' -name 'MicrosoftEventVwrDisableLinks' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000089"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"