
#!/usr/bin/python
################################################################################
# V17669
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
        return r"V-17669"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Smart Documents use of Manifests in Office must be disallowed."

    def get_vulnerability_discussion(self):
        return r"An XML expansion pack is the group of files that constitutes a Smart Document in Excel and Word. One or more components that provide the logic needed for a Smart Document are packaged by using an XML expansion pack. These components can include any type of file, including XML schemas, Extensible Stylesheet Language Transforms (XSLTs), dynamic-link libraries (DLLs), and image files, as well as additional XML files, HTML files, Word files, Excel files, and text files.The key component to building an XML expansion pack is creating an XML expansion pack manifest file. By creating this file, the locations of all files that make up the XML expansion pack are specified, as well as information that instructs Office 2013 how to set up the files for the Smart Document. The XML expansion pack can also contain information about how to set up other files, such as how to install and register a COM object required by the XML expansion pack.XML expansion packs can be used to initialize and load malicious code, which might affect the stability of a computer and lead to data loss. Office applications can load an XML expansion pack manifest file with a Smart Document. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Smart Documents (Word, Excel) ''Disable Smart Document''s use of manifests'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\Common\Smart Tag', 'NeverLoadManifests')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\Common\Smart Tag', ('NeverLoadManifests=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\Common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\Common\Smart Tag'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\Common\Smart Tag' -name 'NeverLoadManifests' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0017"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"