
#!/usr/bin/python
################################################################################
# V17660
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
        return r"V-17660"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Inclusion of document properties for PDF and XPS output must be disallowed."

    def get_vulnerability_discussion(self):
        return r"If the Microsoft Save as PDF or XPS Add-in for Microsoft Office Programs add-in is installed, document properties are saved as metadata when users save files using the PDF or XPS or Publish as PDF or XPS commands in Access 2010, Excel 2010, InfoPath 2010, PowerPoint 2010, and Word 2010, unless the Document properties option is unchecked in the Options dialog box. If this metadata contains sensitive information, saving it with the file could compromise security. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2010 \ Microsoft Save As PDF and XPS add-ins ?Disable inclusion of document properties in PDF and XPS output? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\fixedformat', 'DisableFixedFormatDocProperties')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\fixedformat', ('DisableFixedFormatDocProperties=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\fixedformat'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\fixedformat' -name 'DisableFixedFormatDocProperties' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OS0014"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"