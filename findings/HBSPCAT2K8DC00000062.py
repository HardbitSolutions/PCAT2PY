
#!/usr/bin/python
################################################################################
# V1164
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
        return r"V-1164"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Outgoing secure channel traffic is not signed when possible."

    def get_vulnerability_discussion(self):
        return r"Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked.  If this policy is enabled, all outgoing secure channel traffic should be signed. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Domain Member: Digitally sign secure channel data (when possible)? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters', 'SignSecureChannel')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters', ('SignSecureChannel=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Netlogon'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -name 'SignSecureChannel' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312(e)(2)(ii)"
    
    def get_pci(self):
        return "3.6,4.1,10.5"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000062"
    
    def get_dod8500_2(self):
        return "DCNR-1"

    def get_800_53(self):
        return "AU-10(5), SC-13, SC-13(4)"
    
    def get_iso_27001(self):
        return "A.10.8.4, A.10.9.1, A.10.9.2, A.12.2.3, A.15.1.6"