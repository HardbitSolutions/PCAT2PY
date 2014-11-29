
#!/usr/bin/python
################################################################################
# V36702
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SZ EQ finding
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
        return r"V-36702"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"EMET Default Protections for Internet Explorer must be enabled."

    def get_vulnerability_discussion(self):
        return r"Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR) and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ EMET \ ''Default Protections for Internet Explorer'' to ''Enabled''.The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Policies\Microsoft\EMET\Defaults', 'IE')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\EMET\Defaults', ('IE=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "*\Internet Explorer\iexplore.exe":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\EMET'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\EMET\Defaults' -name 'IE' -value *\Internet Explorer\iexplore.exe")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(B)"
    
    def get_pci(self):
        return "5.1, 5.2"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000326"
    
    def get_dod8500_2(self):
        return "ECVP-1"

    def get_800_53(self):
        return "SI-3"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3"