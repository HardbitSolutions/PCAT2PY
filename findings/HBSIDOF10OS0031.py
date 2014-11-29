
#!/usr/bin/python
################################################################################
# V17773
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
        return r"V-17773"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Vector markup Language (VML) for displaying graphics in browsers must be disallowed."

    def get_vulnerability_discussion(self):
        return r"When saving documents as Web pages, Excel, PowerPoint, and Word can save vector?based graphics in Vector Markup Language (VML), which enables Internet Explorer to display them smoothly at any resolution. By default, when saving VML graphics, Office applications also save copies of the graphics in a standard raster file format (GIF or PNG) for use by browsers that cannot display VML. If the Rely on VML for displaying graphics in browsers check box in the Web Options dialog box is selected, applications will not save raster copies of VML graphics, which means those graphics will not display in non-Microsoft browsers. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2010 \ Tools \ Options \ General \ Web Options \ Browsers ?Rely on VML for displaying graphics in browsers? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet', 'RelyOnVML')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet', ('RelyOnVML=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet' -name 'RelyOnVML' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OS0031"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"