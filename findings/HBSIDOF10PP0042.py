
#!/usr/bin/python
################################################################################
# V26639
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
        return r"V-26639"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The configuration for Slide Update with counterparts must be disallowed."

    def get_vulnerability_discussion(self):
        return r"This setting controls whether users can link slides in a presentation with their counterparts in a PowerPoint Slide Library.  If you enable this policy setting, PowerPoint cannot check the status of a slide in a Slide Library when a presentation with Slide Update data is opened.  If you disable or do not configure this policy setting, each time users open a presentation that contains a shared slide, PowerPoint notifies them if the slide has been updated and provides them with the opportunity to ignore the update, append a new slide to the outdated slide, or replace the outdated slide with the updated one. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft PowerPoint 2010 \ Miscellaneous ?Disable Slide Update? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\slide libraries', 'DisableSlideUpdate')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\slide libraries', ('DisableSlideUpdate=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\slide libraries'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\slide libraries' -name 'DisableSlideUpdate' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10PP0042"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"