
#!/usr/bin/python
################################################################################
# V3348
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
        return r"V-3348"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The user is allowed to launch Windows Messenger (MSN Messenger, .NET Messenger)."

    def get_vulnerability_discussion(self):
        return r"This setting prevents the Windows Messenger client from being run.  Instant Messaging clients must be in compliance of with the Instant Messaging STIG.  Windows Messenger should not be active on Windows unless the instant messaging system is a Managed Enterprise Service for unclassified data for which the DAA has approved. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Windows Messenger ?Do Not Allow Windows Messenger to be Run? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Messenger\Client', 'PreventRun')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Messenger\Client', ('PreventRun=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Messenger'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Messenger\Client'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Messenger\Client' -name 'PreventRun' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000148"
    
    def get_dod8500_2(self):
        return "ECIM-1"

    def get_800_53(self):
        return "SC-15(2)"
    
    def get_iso_27001(self):
        return "A.10.8.1"