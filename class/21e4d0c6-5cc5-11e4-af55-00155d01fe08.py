#!/usr/bin/python
################################################################################
# 21e4d0c6-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "21e4d0c6-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1', '1001')

        # Output Lines
        self.output = [r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1', ('1001=' + str(dword))]

        if dword == 1:
            self.is_compliant = True

        return self.is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1' -name '1001' -value 1 -Type DWord")
