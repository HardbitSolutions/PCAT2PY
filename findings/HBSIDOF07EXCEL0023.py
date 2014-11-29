
#!/usr/bin/python
################################################################################
# V17796
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
        return r"V-17796"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Do not save additional data needed to maintain formulas - Excel."

    def get_vulnerability_discussion(self):
        return r"Microsoft Office Web Components (OWC) is a collection of Component Object Model (COM) controls used by earlier versions of Microsoft Office for publishing spreadsheets, charts, and databases to the Web, and for viewing the published components on the Web. OWC was removed from the 2007 Office release in favor of improvements to the Web features of Office desktop applications and of Microsoft Windows SharePoint Services. Organizations that currently support publishing data to the Web via OWC and are not ready to migrate to newer publishing methods can download OWC from Microsoft and continue to use it with 2007 Microsoft Office applications.By default, when users save workbooks as Web pages that use OWC, Excel maintains externally referenced data of formulas that are not in the selected range to be published, which increases the size of the files and in some cases increases the risk of exposing sensitive information. The user can change this functionality by clearing the Save any additional hidden data necessary to maintain formulas check box on the General tab in the Web Options dialog box (available from the Advanced section of the Excel Options dialog box). If the check box is cleared, Excel 2007 replaces the formulas with calculated values, which reduces the size of the file. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Excel 2007 \ Excel Options \ Advanced \ Web Options \ General ?Save any additional data necessary to maintain formulas? will be set to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Internet', 'DoNotSaveHiddenData')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Internet', ('DoNotSaveHiddenData=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Internet'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Internet' -name 'DoNotSaveHiddenData' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Excel0023"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"