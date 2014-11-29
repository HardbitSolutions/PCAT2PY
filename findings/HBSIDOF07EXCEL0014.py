
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
        return r"Save files default format as backward compatible,  not as XML."

    def get_vulnerability_discussion(self):
        return r"By default, Excel 2007 saves new workbooks in the Office Open XML format with an .xlsx extension. For users who run Excel 2000 with Service Pack 3, Excel 2002 with Service Pack 3, and Excel 2003 with at least Service Pack 1, Microsoft offers the Microsoft Office Compatibility Pack, which enables these versions of Excel to open and save .xlsx files. If some users in your organization cannot install the Compatibility Pack, or are running versions of Excel older than Excel 2000 with Service Pack 3, these users might not be able to access Excel files saved in the .xlsx format. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Excel 2007 \ Excel Options \ Save ''save excel files as'' will be set to ''Enabled (Excel 97-2003 Workbook(*.xls)'' or ''Enabled (Excel Workbook *.xlsx'')."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options', 'DefaultFormat')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options', ('DefaultFormat=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 51:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options' -name 'DefaultFormat' -value 51 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Excel0014"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"