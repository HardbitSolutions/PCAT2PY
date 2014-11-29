
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
        return r"Save files default format  must be configured."

    def get_vulnerability_discussion(self):
        return r"When users create new PowerPoint files, PowerPoint 2010 saves them in the new *.pptx format.  Ensure this setting is enabled to specify that all new files are created in PowerPoint 2010.  If a new file is created in an earlier format, some users may not be able to open or use the file, or they may choose a format this is less secure than the PowerPoint 2010 format.  Users can still select a specific format when they save files, but they cannot change default of this setting from the PowerPoint Options dialog box.  This enforced user behavior ensures any change to the file format requires additional deliberate user interaction. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft PowerPoint 2010 \ PowerPoint Options \ Save ?default file format? to ?Enabled PowerPoint Presentation (*.pptx)''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\options', 'DefaultFormat')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\options', ('DefaultFormat=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 27:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\options'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\powerpoint\options' -name 'DefaultFormat' -value 27 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10PP0016"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"