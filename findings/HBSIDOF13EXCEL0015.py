
#!/usr/bin/python
################################################################################
# V17650
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
        return r"V-17650"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Internet links and Network UNCs created as embedded hyperlinks must be prevented."

    def get_vulnerability_discussion(self):
        return r"When users type a string of characters, Excel recognizes as a Uniform Resource Locator (URL) or Uniform Naming Convention (UNC) path to a resource on the Internet or a local network, Excel will transform it into a hyperlink. Clicking the hyperlink opens it in the configured default web browser or the appropriate application. This functionality can enable users to accidentally create links to dangerous or restricted resources, which could create a security risk. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Excel 2013 \ Excel Options \ Proofing \ Autocorrect Options ''Internet and network paths as hyperlinks'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\options', 'AutoHyperlink')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\options', ('AutoHyperlink=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\excel'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\options'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\excel\options' -name 'AutoHyperlink' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Excel0015"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"