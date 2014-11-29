
#!/usr/bin/python
################################################################################
# V17503
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
        return r"V-17503"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable feature that would block older version of office products from saving files to open XML formats."

    def get_vulnerability_discussion(self):
        return r"The Office Open XML format file types introduced in the 2007 Microsoft Office release offer a number of benefits compared with the previous binary file types supported in Office 2003, including the potential to reduce the effects of malicious code. Files can be identified as unable to run code, and will therefore ignore any embedded code. Also, any files that do have embedded code are easier to identify.For users who run older versions of these applications, Microsoft offers the Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats, which enables them to open and save Open XML files. The Compatibility Pack can be used with the following Microsoft Office programs:?	Word 2000 with Service Pack 3, Excel 2000 with Service Pack 3, and PowerPoint 2000 with Service Pack 3 ?	Word 2002 with Service Pack 3, Excel 2002 with Service Pack 3, and PowerPoint 2002 with Service Pack 3?	Word 2003 with at least Service Pack 1, Excel 2003 with at least Service Pack 1, and PowerPoint 2003 with at least Service Pack 1 ?	Microsoft Office Word Viewer 2003?	Microsoft Office Excel Viewer 2003?	Microsoft Office PowerPoint Viewer 2003If users cannot save files in Office Open XML format for some reason, they will be unable to take advantage of the security benefits of the new file types. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Excel 2007 \ Block file formats \ Save ?Block saving of Open XML file types? will be set to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileSaveBlock', 'OpenXmlFiles')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileSaveBlock', ('OpenXmlFiles=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileSaveBlock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Security\FileSaveBlock' -name 'OpenXmlFiles' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Excel0010"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"