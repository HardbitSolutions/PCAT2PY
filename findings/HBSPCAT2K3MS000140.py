
#!/usr/bin/python
################################################################################
# V3471
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
        return r"V-3471"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system is configured to automatically forward error information."

    def get_vulnerability_discussion(self):
        return r"This setting controls the reporting of errors to Microsoft and, if defined, a corporate error reporting site.  This does not interfere with the reporting of errors to the local user.  Since the contents of memory are included in this Error Report, sensitive information may be transmitted to Microsoft.  This feature should be disabled to prevent the release of such information. Set the policy value for Computer Configuration \ Administrative Templates \ System \ Internet Communication Management \ Internet Communication settings\ ?Turn off Windows Error Reporting? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\PCHealth\ErrorReporting', 'DoReport')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\PCHealth\ErrorReporting', ('DoReport=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\PCHealth'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\PCHealth\ErrorReporting'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\PCHealth\ErrorReporting' -name 'DoReport' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000140"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"