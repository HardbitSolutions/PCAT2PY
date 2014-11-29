
#!/usr/bin/python
################################################################################
# V17521
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
        return r"V-17521"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Save files default format as backward compatible,  not as XML."

    def get_vulnerability_discussion(self):
        return r"By default, Office 2007 producst save new workbooks in the Office Open XML format. For users who run prior versions of Office products, Microsoft offers the Microsoft Office Compatibility Pack, which enables these versions to open and save open XML format. If some users in your organization cannot install the Compatibility Pack, or are running other versions of Office products these users might not be able to access Excel files saved in the Open XML format. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office PowerPoint 2007 \ PowerPoint Options \ Save ?save files in this format? will be set to ?Enabled (PowerPoint 97-2003 Presentation (*.ppt) or Enabled (PowerPoint Presentation (*.pptx)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Options', 'DefaultFormat')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Options', ('DefaultFormat=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 27:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Options'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Options' -name 'DefaultFormat' -value 27 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07PP0020"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"