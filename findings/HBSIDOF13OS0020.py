
#!/usr/bin/python
################################################################################
# V17740
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
        return r"V-17740"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Automatic receiving of small updates to improve reliability must be disallowed."

    def get_vulnerability_discussion(self):
        return r"Having access to updates, add-ins, and patches on the Office Online website can help users ensure computers are up to date and equipped with the latest security patches. However, to ensure updates are tested and applied in a consistent manner, many organizations prefer to roll out updates using a centralized mechanism such as Microsoft Systems Center or Windows Server Update Services.By default, users are allowed to download updates, add-ins, and patches from the Office Online Web site to keep their Office applications running smoothly and securely. If an organization has policies that govern the use of external resources such as Office Online, allowing users to download updates might cause them to violate these policies. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Privacy \ Trust Center ''Automatically receive small updates to improve reliability'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\common', 'UpdateReliabilityData')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\common', ('UpdateReliabilityData=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\common' -name 'UpdateReliabilityData' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0020"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"