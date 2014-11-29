
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
        return r"Pre-release versions of file formats new to Office Products must be blocked."

    def get_vulnerability_discussion(self):
        return r"This policy setting controls whether users with the Microsoft Office Compatibility Pack for Word 2010 File Formats installed can open Office Open XML files saved with pre-release versions of Word 2010. Word Open XML files usually have the following extensions: .docx, .docm, .dotx, .dotm, .xml. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2010 \ Office 2010 Converters ?Block opening of pre-release versions of file formats new to Word 2010 through the Compatibility Pack for Office 2010 and Word 2010 Open XML/Word 97-2003 Format Converter? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\fileblock', 'Word12BetaFilesFromConverters')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\fileblock', ('Word12BetaFilesFromConverters=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\fileblock'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\fileblock' -name 'Word12BetaFilesFromConverters' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010Word"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10Word0007"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"