
#!/usr/bin/python
################################################################################
# V21961
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SZ EQ finding
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
        return r"V-21961"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"All Direct Access traffic will be routed through the internal network."

    def get_vulnerability_discussion(self):
        return r"This setting ensures all traffic is routed through the internal network, allowing monitoring and preventing split tunneling. Set the policy value for Computer Configuration \ Administrative Templates \ Network \ Network Connections \ ?Route all traffic through the internal network? to ?Enabled: Enabled State?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition', 'Force_Tunneling')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition', ('Force_Tunneling=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "Enabled":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\TCPIP'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition' -name 'Force_Tunneling' -value Enabled")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000173"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"