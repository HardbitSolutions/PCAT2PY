
#!/usr/bin/python
################################################################################
# V4442
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SZ LE finding
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-4442"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"This check verifies that Windows is configured to have password protection take effect within a limited time frame when the screen saver becomes active."

    def get_vulnerability_discussion(self):
        return r"Allowing more than several seconds makes the computer vulnerable to a potential attack from someone walking up to the console to attempt to log onto the system before the lock takes effect. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)? to ?5? or less."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'ScreenSaverGracePeriod')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', ('ScreenSaverGracePeriod=' + sz)]

        if self.__verbose:
            print self.__output

        try:
		if int(sz) <= 5:
            		self.__is_compliant = True
	except ValueError:
		None

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'ScreenSaverGracePeriod' -value 5")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return "164.310(b),164.312(a)(2)(iii)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000239"
    
    def get_dod8500_2(self):
        return "PESL-1"

    def get_800_53(self):
        return "AC-11"
    
    def get_iso_27001(self):
        return "A.11.3.2, A.11.3.3, A.11.5.5"