#!/usr/bin/python
################################################################################
# 252e2390-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "252e2390-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\common\feedback', 'enabled')

        # Output Lines
        self.output = [r'HKCU:\software\policies\Microsoft\office\15.0\common\feedback', ('enabled=' + str(dword))]

        if dword == 0:
            self.is_compliant = True

        return self.is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\common\feedback'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\common\feedback' -name 'enabled' -value 0 -Type DWord")
