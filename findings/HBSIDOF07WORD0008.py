
#!/usr/bin/python
################################################################################
# V17322
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
        return r"V-17322"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Block opening of pre-release versions of file formats new to Word 2007 through the Compatibility Pack for the 2007 Office system and Word 2007 Open XML/Word 97-2003 Format Converter - System"

    def get_vulnerability_discussion(self):
        return r"The Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats enables users of Microsoft Word 2000, Word 2002, and Office Word 2003 to open files saved in the Office Open XML format used by Word 2007. Word Open XML files usually have the following extensions: ?	.docx?	.docm?	.dotx?	.dotm?	.xmlBy default, the Compatibility Pack does not open files that were saved in pre-release versions of the new Office Open XML format, which underwent some minor changes prior to the final release of Word 2007. If this configuration is changed, through a registry modification or by some other mechanism, users with the Compatibility Pack installed can open files saved by some pre-release versions of Word, but not by others, which can lead to inconsistent file opening functionality. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2007 system \ Office 2007 Converters ?Block opening of pre-release versions of file formats new to Word 2007 through the Compatibility Pack for the 2007 Office system and Word 2007 Open XML/Word 97-2003 Format Converter? will be set to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Word\Security\FileOpenBlock', 'Word12BetaFilesFromConverters')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Word\Security\FileOpenBlock', ('Word12BetaFilesFromConverters=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Word'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Word\Security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Word\Security\FileOpenBlock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Word\Security\FileOpenBlock' -name 'Word12BetaFilesFromConverters' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Word"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Word0008"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"