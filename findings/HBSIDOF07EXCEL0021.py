
#!/usr/bin/python
################################################################################
# V17744
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
        return r"V-17744"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"AutoRepublish Warning Alert should be enabled - Excel"

    def get_vulnerability_discussion(self):
        return r"AutoRepublish is a feature in Excel 2007 that allows workbooks to be automatically republished to the World Wide Web each time the workbook is saved. A number of changes might need to be made to allow the workbook to be successfully published, including the following:?	External references are converted to values.?	Hidden formulas become visible.?	The Set precision as displayed option, which appears beneath the When calculating this workbook heading in the Advanced section of the Excel Options dialog box, is no longer available.These types of changes can mean that the version on the Web page might not be the same as the Excel file.By default, a message dialog box appears every time the user saves a published workbook when AutoRepublish is enabled. From this dialog box, the user can disable AutoRepublish temporarily or permanently, or select Do not show this message again to prevent the dialog box from appearing after every save. If the user selects Do not show this message again, Excel will continue to automatically republish the data after every save without informing the user. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Excel 2007 \ Excel Options \ Save ?AutoRepublish Warning Alert? will be set to ?Enabled (Always show the alert before publishing)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options', 'DisableAutoRepublishWarning')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options', ('DisableAutoRepublishWarning=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options' -name 'DisableAutoRepublishWarning' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Excel0021"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"