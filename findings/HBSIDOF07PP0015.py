
#!/usr/bin/python
################################################################################
# V17473
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
        return r"V-17473"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Determine whether to force encrypted macros to be scanned in open XML presentations."

    def get_vulnerability_discussion(self):
        return r"When an Office Open XML document (Word, Excel, Powerpoint) is rights-managed or password-protected, any macros that are embedded in the document are encrypted along with the rest of the contents.  By default, these encrypted macros will be disabled unless they are scanned by antivirus software immediately before being loaded. If this default configuration is modified, Office 2007 products will not require encrypted macros to be scanned before loading. They will be handled as specified by the Office 2007 System macro security settings, which can cause macro viruses to load undetected and lead to data loss or reduced application functionality. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office PowerPoint 2007 \ PowerPoint Options \ Security ?Determine whether to force encrypted macros to be scanned in Microsoft PowerPoint Open XML presentations? will be set to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security', 'PowerPointBypassEncryptedMacroScan')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security', ('PowerPointBypassEncryptedMacroScan=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\PowerPoint\Security' -name 'PowerPointBypassEncryptedMacroScan' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07PP0015"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"