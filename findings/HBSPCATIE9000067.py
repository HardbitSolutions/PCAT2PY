
#!/usr/bin/python
################################################################################
# V15525
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
        return r"V-15525"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"First-Run Opt-In ability must be disallowed (Internet zone)."

    def get_vulnerability_discussion(self):
        return r"This policy setting controls the First Run response that users see on a zone-by-zone basis. When a user encounters a new control that has not previously run in Internet Explorer, they may be prompted to approve the control. This feature determines if the user gets the prompt or not. If you enable this policy setting, the Gold Bar prompt will be turned off in the corresponding zone. If you disable this policy setting, the Gold Bar prompt will be turned on in the corresponding zone. If you do not configure this policy setting, the first-run prompt is turned off by default. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> ''Turn Off First-Run Opt-In'' to ?Enabled? and select ''Disable'' from the drop-down box."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3', '1208')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3', ('1208=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -name '1208' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE9"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE9000067"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"