
#!/usr/bin/python
################################################################################
# V17561
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
        return r"V-17561"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Choice of output to include PNG (Portable Network Graphics) must be disallowed."

    def get_vulnerability_discussion(self):
        return r"Office files can save graphic files in Portable Network Graphics (PNG) format to improve the quality of the graphics when documents are saved as web pages. The PNG graphic file format (.png) is used for a wide range of graphics, from small images (such as bullets and banners) to complex images (such as photographs), and can offer better image fidelity and smaller file sizes than some other formats. However, PNG graphics cannot be displayed by many earlier web browsers, such as Microsoft Internet Explorer version 5 or earlier.Office applications do not save graphics in the PNG format by default but can be configured to save in PNG format by explicitly enabling this setting. By disabling this setting, future zero-day attacks that target PNG files will be thwarted. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Tools \ Options \ General \ Web Options \ Browsers ''Allow PNG as an output format''  to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\common\internet', 'AllowPNG')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\common\internet', ('AllowPNG=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common\internet'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common\internet' -name 'AllowPNG' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0003"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"