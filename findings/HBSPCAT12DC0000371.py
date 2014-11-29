
#!/usr/bin/python
################################################################################
# V36705
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
        return r"V-36705"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Enhanced Mitigation Experience Toolkit (EMET) system-wide Data Execution Prevention (DEP) must be enabled and configured to at least Application Opt Out."

    def get_vulnerability_discussion(self):
        return r"Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications, adding additional levels of protection. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ EMET \ ''System DEP'' to ''Enabled'' with at least ''Application Opt-Out'' selected. The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.Document applications that do not function properly due to this setting, and are opted out, with the IAO.Opted out exceptions can be configured with the following command:EMET_Conf --Set ''application path\executable name'' -DEPAlternately, configure exceptions in System Properties:Select ''System'' in Control Panel.Select ''Advanced system settings''.Click ''Settings'' in the ''Performance'' section.Select the ''Data Execution Prevention'' tab.Select ''Turn on DEP for all programs and services except those I select:''.Applications that are opted out are configured in the window below this selection."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\EMET\SysSettings', 'DEP')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\EMET\SysSettings', ('DEP=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\EMET'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings' -name 'DEP' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(B)"
    
    def get_pci(self):
        return "5.1, 5.2"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000371"
    
    def get_dod8500_2(self):
        return "ECVP-1"

    def get_800_53(self):
        return "SI-3"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3"