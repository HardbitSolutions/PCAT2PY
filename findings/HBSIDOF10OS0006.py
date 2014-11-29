
#!/usr/bin/python
################################################################################
# V17588
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
        return r"V-17588"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Access to updates, add-ins, and patches on Office.com must be disabled."

    def get_vulnerability_discussion(self):
        return r"Having access to updates, add-ins, and patches on the Office Online Web site can help users ensure computers are up to date and equipped with the latest security patches. However, to ensure updates are tested and applied in a consistent manner, many organizations prefer to roll out updates using a centralized mechanism such as Microsoft Systems Center or Windows Server Update Services.By default, users are allowed to download updates, add-ins, and patches from the Office Online Web site to keep their Office applications running smoothly and securely. If your organization has policies that govern the use of external resources such as Office Online, allowing users to download updates might cause them to violate these policies. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2010 \ Tools \ Options \ General \ Web Options... ?Disable access to updates, add-ins, and patches on Office.com? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet', 'DisableDownloadCenterAccess')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet', ('DisableDownloadCenterAccess=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\common\internet' -name 'DisableDownloadCenterAccess' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OS0006"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"