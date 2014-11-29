
#!/usr/bin/python
################################################################################
# V30778
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
        return r"V-30778"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"ActiveX opt-in prompt is not disabled."

    def get_vulnerability_discussion(self):
        return r"This policy setting allows you to turn off the ActiveX opt-in prompt. The ActiveX opt-in prevents Web sites from loading any COM object without prior approval.  If a page attempts to load a COM object that Internet Explorer has not used before, an Information bar will appear asking the user for approval.  If you enable this policy setting, the ActiveX opt-in prompt will not appear.  Internet Explorer does not ask the user for permission to load a control, and will load the ActiveX if it passes all other internal security checks.  If you disable or do not configure this policy setting the ActiveX opt-in prompt will appear. Manipulate the value:HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext Criteria: Set the value NoFirsttimeprompt to REG_DWORD = 1."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext', 'NoFirsttimeprompt')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext', ('NoFirsttimeprompt=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext' -name 'NoFirsttimeprompt' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE8"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE8000116"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"