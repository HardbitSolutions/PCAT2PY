#!/usr/bin/python
################################################################################
# 214373e8-5cc5-11e4-af55-00155d01fe08
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# 10/24/2014 Original Construction
################################################################################

class Finding:
    def __init__(self):
        self.output = []
        self.is_compliant = False
        self.uuid = "214373e8-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters', 'TcpMaxDataRetransmissions')

        # Output Lines
        self.output = [r'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters', ('TcpMaxDataRetransmissions=' + str(dword))]

        if dword <= 3:
            self.is_compliant = True

        return self.is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters' -name 'TcpMaxDataRetransmissions' -value 3 -Type DWord")
