#!/usr/bin/python
################################################################################
# V3340
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MULTISZ EQ finding
#
# 09/23/2014 Original Construction
# 10/09/2014 Fixed equality statement to [''] instead on NULL
#            Changed fix method respectfully
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
        return "CAT I"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-3340"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Network shares that can be accessed anonymously will not be allowed."

    def get_vulnerability_discussion(self):
        return r"This is a high priority finding because the potential for gaining unauthorized system access. Any shares listed can be accessed by any network user.  This could lead to the exposure or corruption of sensitive data.  Enabling this setting is very dangerous. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Network access: Shares that can be accessed anonymously? to be defined but containing no entries (Blank)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry MULTI_SZ
        multi_sz = cli.get_reg_multi_sz(r'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters', 'NullSessionShares')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters', ('NullSessionShares=')] + multi_sz

        if self.__verbose:
            print self.__output

        if multi_sz == ['']:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\LanManServer'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -name 'NullSessionShares' -Type MultiString -value $null")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000278"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"