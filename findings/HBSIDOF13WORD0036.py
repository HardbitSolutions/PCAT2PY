
#!/usr/bin/python
################################################################################
# V41147
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
        return r"V-41147"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Word must be configured to warn when opening a document with custom XML markup."

    def get_vulnerability_discussion(self):
        return r"This policy setting specifies how Word behaves when opening a document that contains custom XML markup. Versions of Word that are distributed by Microsoft after January 10, 2010 no longer read the custom XML markup that may be contained within (.docx, .docm, .dotx, .dotm or .xml files. The new versions of Word 2007, Word 2010, and Word 2013 can still open these files, but any custom XML markup is removed. Configuring this setting will prompt the user with a warning, notifying of the lost of the XML markup. While this is the default setting, explicitly configuring the setting will ensure users are prompted. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Word 2013 \ Word Options \ Advanced \ ''Custom markup warning'' to ''Enabled: Prompt''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\word\options', 'custommarkupwarning')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\word\options', ('custommarkupwarning=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\options'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\options' -name 'custommarkupwarning' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Word"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Word0036"
    
    def get_dod8500_2(self):
        return ""

    def get_800_53(self):
        return ""
    
    def get_iso_27001(self):
        return ""