#!/usr/bin/python
################################################################################
# 214b9230-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "214b9230-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Security', 'NoTBPromptUnsignedAddin')

        # Output Lines
        self.output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Security', ('NoTBPromptUnsignedAddin=' + str(dword))]

        if dword == 1:
            self.is_compliant = True

        return self.is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Access\Security' -name 'NoTBPromptUnsignedAddin' -value 1 -Type DWord")