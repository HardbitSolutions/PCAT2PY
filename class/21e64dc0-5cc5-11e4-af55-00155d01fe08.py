#!/usr/bin/python
################################################################################
# 21e64dc0-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "21e64dc0-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT', 'spDesign.exe')

        # Output Lines
        self.output = [r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT', ('spDesign.exe=' + str(dword))]

        if dword == 1:
            self.is_compliant = True

        return self.is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT' -name 'spDesign.exe' -value 1 -Type DWord")