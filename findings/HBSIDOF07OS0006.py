
#!/usr/bin/python
################################################################################
# V17583
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
        return r"V-17583"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Allow users with earlier versions of Office to read with browsers - System"

    def get_vulnerability_discussion(self):
        return r"The Windows Rights Management Add-on for Internet Explorer provides a way for users who do not use the 2007 Office release to view, but not alter, files with restricted permissions. By default, IRM-enabled files are saved in a format that cannot be viewed by using the Windows Rights Management Add-on. If this setting is enabled, an embedded rights-managed HTML version of the content is saved with each IRM-enabled file, which can be viewed in Internet Explorer using the add-on. This configuration increases the size of rights-managed files, in some cases significantly. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2007 system \ Manage Restricted Permissions ?Allow users with earlier versions of Office to read with browsers? will be set to ''Disabled''.''Note: Group Policy Administrative Templates are available from the www.microsoft.com download site. The MS Office 2007 System (Office12.adm) is included in the AdminTemplates.exe file. This template provides themechanisms to incorporate Microsoft Office 2007 System policies via the Microsoft Group Policy Editor (gpedit.msc).''''Note: If the Microsoft Group Policy Editor (gpedit.msc) is not used to incorporate the remediation to this vulnerability the Microsoft Registry Editor (regedit.exe) may be used to create the registry key and value required.''"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM', 'IncludeHTML')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM', ('IncludeHTML=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM' -name 'IncludeHTML' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07OS0006"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"