
#!/usr/bin/python
################################################################################
# V1122C
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
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1122C"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system will be configured with a password-protected screen saver."

    def get_vulnerability_discussion(self):
        return r"The system should be locked when unattended.  Unattended systems are susceptible to unauthorized use.  The screen saver should be set at a maximum of 15 minutes and password protected.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer. Set the policy values for User Configuration \ Administrative Templates \ Control Panel \ Personalization \ as follows:?Enable Screen Saver? will be set to ?Enabled?.?Password protect the screen saver? will be set to ?Enabled?.?Screen Saver timeout? will be set to ?Enabled: 900 seconds? (or less)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', 'ScreenSaveTimeOut')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', ('ScreenSaveTimeOut=' + sz)]

        if self.__verbose:
            print self.__output

        try:
		if int(sz) <= 900:
            		self.__is_compliant = True
	except ValueError:
		None

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -name 'ScreenSaveTimeOut' -value 900")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.310(b),164.312(a)(2)(iii)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000032"
    
    def get_dod8500_2(self):
        return "PESL-1"

    def get_800_53(self):
        return "AC-11"
    
    def get_iso_27001(self):
        return "A.11.3.2, A.11.3.3, A.11.5.5"