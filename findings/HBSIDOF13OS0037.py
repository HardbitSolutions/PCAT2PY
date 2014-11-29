
#!/usr/bin/python
################################################################################
# V40863
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
        return r"V-40863"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The ability to automatically hyperlink screenshots within Word, PowerPoint, Excel and Outlook must be disabled."

    def get_vulnerability_discussion(self):
        return r"The ability to automatically bind hyperlink to a screenshot inserted through the Insert Screenshot tool introduces the possibility of a malicious URL or website being imbedded in the Word, PowerPoint, Excel or Outlook document. Disabling the hyperlink in those screenshots will ensure users do not have the ability to directly open the hyperlinks. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Miscellaneous \ ''Do not automatically hyperlink screenshots'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\gfx', 'disablescreenshotautohyperlink')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\gfx', ('disablescreenshotautohyperlink=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\gfx'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\gfx' -name 'disablescreenshotautohyperlink' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0037"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"