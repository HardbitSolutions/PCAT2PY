
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
        return r"Disable Automatic receiving of small updates to improve reliability - Office."

    def get_vulnerability_discussion(self):
        return r"Office Diagnostics is used to improve the user experience by periodically downloading a small file to the computer with updated help information about specific problems. If Office Diagnostics is enabled, it collects information about specific errors and the IP address of the computer. When new help information is available, that help information is downloaded to the computer that experienced the related problems. Office Diagnostics does not transmit any personally identifiable information to Microsoft other than the IP address of the computer requesting the update. By default, users have the opportunity to opt into receiving updates from Office Diagnostics the first time they run a 2007 Office application. If your organization has policies that govern the use of external resources such as Office Diagnostics, allowing users to opt in to this feature might cause them to violate these policies. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2007 system \ Privacy \ Trust Center ?Automatically receive small updates to improve reliability? will be set to ?Disabled?.''Note: Group Policy Administrative Templates are available from the www.microsoft.com download site. The MS Office 2007 System (Office12.adm) is included in the AdminTemplates.exe file. This template provides themechanisms to incorporate Microsoft Office 2007 System policies via the Microsoft Group Policy Editor (gpedit.msc).''''Note: If the Microsoft Group Policy Editor (gpedit.msc) is not used to incorporate the remediation to this vulnerability the Microsoft Registry Editor (regedit.exe) may be used to create the registry key and value required.''"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common', 'UpdateReliabilityData')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common', ('UpdateReliabilityData=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common' -name 'UpdateReliabilityData' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07OS0024"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"