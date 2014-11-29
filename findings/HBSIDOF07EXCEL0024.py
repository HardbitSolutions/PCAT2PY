
#!/usr/bin/python
################################################################################
# V17804
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
        return r"V-17804"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Store macro in Personal macro Workbook by default - Excel."

    def get_vulnerability_discussion(self):
        return r"The Record Macro dialog box includes a drop-down menu that allows users to choose whether to store the new macro in the current workbook, a new workbook, or their personal macro workbook (Personal.xlsb), a hidden workbook that opens every time Excel 2007 starts.By default, Excel displays the Record Macro dialog box with This Workbook already selected in the drop-down menu. If a user saves a macro in the active workbook and then distributes the workbook to others, the macro is distributed along with the workbook, which could put workbook data at risk if the macro is triggered accidentally or intentionally. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office Excel 2007 \ Excel Options \ Security \ Trust Center ?Store macro in Personal Macro Workbook by default? will be set to ?Enabled?.Procedure:  Use the Windows Registry Editor to navigate to the following key: HKCU\Software\Policies\Microsoft\Office\12.0\Excel\Options\BinaryOptionsCriteria: If the value fGlobalSheet_37_1 is REG_DWORD = 1, this is not a finding."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options\BinaryOptions', 'fGlobalSheet_37_1')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options\BinaryOptions', ('fGlobalSheet_37_1=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options\BinaryOptions'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Excel\Options\BinaryOptions' -name 'fGlobalSheet_37_1' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07Excel0024"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"