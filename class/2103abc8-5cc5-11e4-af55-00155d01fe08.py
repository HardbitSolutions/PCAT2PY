#!/usr/bin/python
################################################################################
# 2103abc8-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "2103abc8-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer', 'NoDriveTypeAutorun')

        # Output Lines
        self.output = [r'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer', ('NoDriveTypeAutorun=' + str(dword))]

        if dword == 255:
            self.is_compliant = True

        return self.is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies'")
        cli.powershell(r"New-Item -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -name 'NoDriveTypeAutorun' -value 255 -Type DWord")
