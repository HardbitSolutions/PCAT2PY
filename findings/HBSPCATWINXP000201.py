
#!/usr/bin/python
################################################################################
# V4437
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD RANGE finding
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
        return r"V-4437"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"TCP connection response retransmissions are not controlled."

    def get_vulnerability_discussion(self):
        return r"In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and no longer is able to respond to legitimate requests. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?MSS: (TcpMaxConnectResponseRetransmissions) SYN-ACK retransmissions when a connection is not acknowledged? to ?3 & 6 seconds, half-open connections dropped after 21 seconds?,  ?3 seconds, half-open connections dropped after 9 seconds? or ?No retransmission, half-open connections dropped after 3 seconds?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters', 'TcpMaxConnectResponseRetransmissions')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters', ('TcpMaxConnectResponseRetransmissions=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword >= 0  or dword <=  2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -name 'TcpMaxConnectResponseRetransmissions' -value 0 to 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000201"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"