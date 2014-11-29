#!/usr/bin/python
################################################################################
# V15713
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD NE finding
#
# 09/21/2014 Original Construction
# 10/03/2014 Fixed check method condition statement
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
        return r"V-15713"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Microsoft Active Protection Service membership must be disabled."

    def get_vulnerability_discussion(self):
        return r"Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting disables Microsoft Active Protection Service membership and reporting. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Windows Defender \ ''Configure Microsoft Active Protection Service Reporting '' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet', 'SpyNetReporting')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet', ('SpyNetReporting=' + str(dword))]

        if self.__verbose:
            print self.__output

        if not (dword == 1 or dword == 2):
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows Defender'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet' -name 'SpyNetReporting' -value Not Equal 1 or 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000123"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"