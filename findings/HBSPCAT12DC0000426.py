
#!/usr/bin/python
################################################################################
# V4112
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
        return r"V-4112"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system must be configured to disable the Internet Router Discovery Protocol (IRDP)."

    def get_vulnerability_discussion(self):
        return r"The Internet Router Discovery Protocol (IRDP) is used to detect and configure default gateway addresses on the computer.  If a router is impersonated on a network, traffic could be routed through the compromised system. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)'' to ''Disabled''.(See ''Updating the Windows Security Options File'' in the STIG Overview document if MSS settings are not visible in the system''s policy tools.)"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters', 'PerformRouterDiscovery')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters', ('PerformRouterDiscovery=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -name 'PerformRouterDiscovery' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000426"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"