
#!/usr/bin/python
################################################################################
# V14262
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
        return r"V-14262"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"IPv6 will be disabled until a deliberate transition strategy has been implemented.  Use of IPv6 transition technologies will be disabled."

    def get_vulnerability_discussion(self):
        return r"Any nodes? interface with IPv6 enabled by default presents a potential risk of traffic being transmitted or received without proper risk mitigation strategy and therefore a serious security concern. Add the following registry key.To disable IPv6 on all interfaces:Registry Hive: HKEY_LOCAL_MACHINESubkey: System\CurrentControlSet\Services\Tcpip6\ParametersValue Name: DisabledComponentsType: REG_DWORDValue: 0xffffffffTo disable all IPv6 tunneling interfaces:Registry Hive: HKEY_LOCAL_MACHINESubkey: System\CurrentControlSet\Services\Tcpip6\ParametersValue Name: DisabledComponentsType: REG_DWORDValue: 0x1Discrepancies in documentation have resulted in several changes to this requirement.  See Microsoft article 929852 for details of the DisabledComponents registry value."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters', 'DisabledComponents')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters', ('DisabledComponents=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0xffffffff:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters' -name 'DisabledComponents' -value 0xffffffff -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000099"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"