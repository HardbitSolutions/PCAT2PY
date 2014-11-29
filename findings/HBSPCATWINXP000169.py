
#!/usr/bin/python
################################################################################
# V3455
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
        return r"V-3455"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Terminal Services is configured to use a common temporary folder for all sessions."

    def get_vulnerability_discussion(self):
        return r"This setting, which is located under the Temporary Folders section of the Terminal Services configuration option, controls the use of per session temporary folders or of a communal temporary folder.  If this setting is enabled, only one temporary folder is used for all terminal services sessions.  If a communal temporary folder is used, it might be possible for users to access other users temporary folders. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Terminal Services \ Temporary Folders ?Do Not Use Temp Folders per Session? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', 'PerSessionTempDir')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', ('PerSessionTempDir=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -name 'PerSessionTempDir' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000169"
    
    def get_dod8500_2(self):
        return "ECRC-1"

    def get_800_53(self):
        return "SC-4"
    
    def get_iso_27001(self):
        return ""