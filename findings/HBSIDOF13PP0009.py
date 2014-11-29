
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
        return r"Enforce encrypted macros to be scanned in open XML documents must be determined and configured."

    def get_vulnerability_discussion(self):
        return r"When an Office Open XML document (Word, Excel, and PowerPoint) is rights-managed, or password-protected, any macros embedded in the document are encrypted along with the rest of the contents.  By default, these encrypted macros will be disabled unless they are scanned by antivirus software immediately before being loaded. If this default configuration is modified, Office products will not require encrypted macros to be scanned before loading. They will be handled as specified by the Office System macro security settings, which can cause macro viruses to load undetected and lead to data loss or reduced application functionality. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft PowerPoint 2013 \ PowerPoint Options \ Security ''Scan encrypted macros in PowerPoint Open XML presentations'' to ''Enabled (Scan encrypted macros (default)''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\security', 'PowerPointBypassEncryptedMacroScan')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\security', ('PowerPointBypassEncryptedMacroScan=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\powerpoint\security' -name 'PowerPointBypassEncryptedMacroScan' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13PP0009"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"