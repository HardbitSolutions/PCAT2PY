
#!/usr/bin/python
################################################################################
# V26613
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
        return r"V-26613"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Open/Save actions for Web pages and Excel 2003 XML spreadsheets must be blocked."

    def get_vulnerability_discussion(self):
        return r"This policy setting allows for determining whether users can open, view, edit, or save Excel files with the format specified by the title. If enabling this policy setting, specify whether users can open, view, edit, or save files. The options that can be selected are below. Note: Not all options may be available for this policy setting. - Do not block: The file type will not be blocked. - Save blocked: Saving of the file type will be blocked. - Open/Save blocked, use open policy: Both opening and saving of the file type will be blocked. The file will open based on the policy setting configured in the ''default file block behavior'' key. - Block: Both opening and saving of the file type will be blocked, and the file will not open. - Open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit the file type will not be enabled. - Allow editing and open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit will be enabled. If you disable or do not configure this policy setting, the file type will not be blocked. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Excel 2010 \ Excel Options \ Security \ Trust Center \ File Block Settings ?Web pages and Excel 2003 XML spreadsheets? to ?Enabled: Open/Save blocked, use open policy''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\excel\security\fileblock', 'HtmlandXmlssFiles')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\excel\security\fileblock', ('HtmlandXmlssFiles=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\excel\security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\excel\security\fileblock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\excel\security\fileblock' -name 'HtmlandXmlssFiles' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10Excel0042"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"