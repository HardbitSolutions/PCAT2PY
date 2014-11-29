
#!/usr/bin/python
################################################################################
# V26610
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
        return r"V-26610"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Actions for Excel 95 workbooks must be configured to edit in Protected View."

    def get_vulnerability_discussion(self):
        return r"This setting specifies whether users can open, view, edit, or save files saved in the specified format. Enabling block of the specified format mitigates zero-day security attacks (which are attacks that occur between the time that a vulnerability becomes publicly known and a software update or service pack is available) by temporarily preventing users from opening specific types of files and to prevent a user from opening files that have been saved in earlier and pre-release (beta) Microsoft Office formats. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Excel 2013 \ Excel Options \ Security \ Trust Center \ File Block Settings ''Excel 95 workbooks'' to ''Enabled: Allow editing and open in Protected View''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\security\fileblock', 'XL95Workbooks')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\security\fileblock', ('XL95Workbooks=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 5:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\security\fileblock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\security\fileblock' -name 'XL95Workbooks' -value 5 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Excel0037"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"