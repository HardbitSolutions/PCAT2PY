
#!/usr/bin/python
################################################################################
# V17732
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
        return r"V-17732"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Update of automatic links setting must be configured to prompt user before allowing links to be updated."

    def get_vulnerability_discussion(self):
        return r"If an Excel workbook contains links to other documents and users are not prompted to approve them, the contents of the workbook might change without the users'' knowledge because the linked files have changed. This has the risk of introducing corrupt or malicious content into the document. Prompting the user to update links will allow the content to be updated only with the user''s knowledge. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Excel 2013 \ Excel options \ Advanced \ ''Ask to update automatic links'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\excel\options\binaryoptions', 'fUpdateExt_78_1')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\excel\options\binaryoptions', ('fUpdateExt_78_1=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\excel'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\excel\options'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\excel\options\binaryoptions'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\excel\options\binaryoptions' -name 'fUpdateExt_78_1' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Excel0017"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"