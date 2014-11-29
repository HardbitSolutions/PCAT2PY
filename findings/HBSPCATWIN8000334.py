
#!/usr/bin/python
################################################################################
# V36710
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-36710"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Automatic download of updates from the Windows Store must be turned off."

    def get_vulnerability_discussion(self):
        return r"Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially allow sensitive information outside of the enterprise.  Application updates must be obtained from an internal source. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Store \ ''Turn off Automatic Download of updates'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\WindowsStore\WindowsUpdate', 'AutoDownload')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\WindowsStore\WindowsUpdate', ('AutoDownload=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\WindowsStore'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\WindowsStore\WindowsUpdate'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\WindowsStore\WindowsUpdate' -name 'AutoDownload' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000334"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"