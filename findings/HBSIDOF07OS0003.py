
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-17561"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Do not allow choice of output to include PNG (Portable Network Graphics)"

    def get_vulnerability_discussion(self):
        return r"Excel 2007, PowerPoint 2007, and Word 2007 can save graphic files in Portable Network Graphics (PNG) format to improve the quality of the graphics when documents are saved as Web pages. The PNG graphic file format (.png) is used for a wide range of graphics, from small images (such as bullets and banners) to complex images (such as photographs), and can offer better image fidelity and smaller file sizes than some other formats. However, PNG graphics cannot be displayed by many earlier Web browsers, such as Microsoft Internet Explorer? version 5 or earlier.By default, Office applications do not save graphics in the PNG format. To change this functionality, users can open the application''s Options dialog box, click Advanced, click Web Options, and then select the Allow PNG as a graphics format check box.This setting can be used to guard against theoretical future zero-day attacks that might target PNG files. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2007 system \ Tools \ Options \ General \ Web Options \ Browsers ?Allow PNG as an output format? will be set to ?Disabled?.''Note: Group Policy Administrative Templates are available from the www.microsoft.com download site. The MS Office 2007 System (Office12.adm) is included in the AdminTemplates.exe file. This template provides themechanisms to incorporate Microsoft Office 2007 System policies via the Microsoft Group Policy Editor (gpedit.msc).''''Note: If the Microsoft Group Policy Editor (gpedit.msc) is not used to incorporate the remediation to this vulnerability the Microsoft Registry Editor (regedit.exe) may be used to create the registry key and value required.''"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Internet', 'AllowPNG')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Internet', ('AllowPNG=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Internet'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\Internet' -name 'AllowPNG' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07OS0003"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"