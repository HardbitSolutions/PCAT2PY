
#!/usr/bin/python
################################################################################
# V17664
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
        return r"V-17664"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Opt-In Wizard must be disabled."

    def get_vulnerability_discussion(self):
        return r"The Opt-in Wizard displays the first time users run a 2010 Microsoft Office application, which allows them to opt into Internet?based services that will help improve their Office experience, such as Microsoft Update, the Customer Experience Improvement Program, Office Diagnostics, and Online Help. If your organization has policies that govern the use of such external resources, allowing users to opt in to these services might cause them to violate the policies. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2010 \ Privacy \ Trust Center ?Disable Opt-in Wizard on first run? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\general', 'ShownFirstRunOptin')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\general', ('ShownFirstRunOptin=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\general'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\general' -name 'ShownFirstRunOptin' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OS0017"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"