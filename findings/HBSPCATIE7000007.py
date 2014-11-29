
#!/usr/bin/python
################################################################################
# V6245
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
        return r"V-6245"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Initialize and script ActiveX controls not marked as safe for internet zone is not disabled."

    def get_vulnerability_discussion(self):
        return r"This policy setting allows you to manage ActiveX controls not marked as safe.If you enable this policy setting, ActiveX controls are run, loaded with parameters, and scripted without setting object safety for untrusted data or scripts. This setting is not recommended, except for secure and administered zones. This setting causes both unsafe and safe controls to be initialized and scripted, ignoring the Script ActiveX controls marked safe for scripting option.If you enable this policy setting and select Prompt in the drop-down box, users are queried whether to allow the control to be loaded with parameters or scripted.  If you disable this policy setting, ActiveX controls that cannot be made safe are not loaded with parameters or scripted.  If you do not configure this policy setting, ActiveX controls that cannot be made safe are not loaded with parameters or scripted. Manipulate the value: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3Criteria: Set the value 1201 to REG_DWORD = 3."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3', '1201')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3', ('1201=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -name '1201' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE7"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE7000007"
    
    def get_dod8500_2(self):
        return "DCMC-1"

    def get_800_53(self):
        return "SC-18, SC-18(2), SC-18(3), SC-18(4)"
    
    def get_iso_27001(self):
        return "A.10.4.2, A.12.4.1"