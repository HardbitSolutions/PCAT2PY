
#!/usr/bin/python
################################################################################
# V15490
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
        return r"V-15490"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Automatic configuration of Internet Explorer is not disabled."

    def get_vulnerability_discussion(self):
        return r"This setting specifies to automatically detect the proxy server settings used to connect to the Internet and customize Internet Explorer. This setting specifies that Internet Explorer use the configuration settings provided in a file by the system administrator.  If you enable this policy setting, the user will not be able to do automatic configuration. You can import your current connection settings from your machine using Internet Explorer Maintenance under Admin Templates using group policy editor.  If you disable or do no configure this policy setting, the user will have the freedom to automatically configure these settings. Manipulate the value: HKLM\Software\Policies\Microsoft\Internet Explorer\Control Panel Criteria: Set the value Autoconfig to REG_DWORD = 1 (Hex)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel', 'Autoconfig')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel', ('Autoconfig=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel' -name 'Autoconfig' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE8"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE8000041"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"