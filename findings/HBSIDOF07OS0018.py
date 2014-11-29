
#!/usr/bin/python
################################################################################
# V17662
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
        return r"V-17662"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable Microsoft passport Service for content with restricted permissions - Office."

    def get_vulnerability_discussion(self):
        return r"The Information Rights Management feature of the 2007 Microsoft Office release allows individuals and administrators to specify access permissions to Word 2007 documents, Excel 2007 workbooks, PowerPoint 2007 presentations, and Outlook 2007 e-mail messages. This capability helps prevent sensitive information from being printed, forwarded, or copied by unauthorized people. Users protect content using digital certificates obtained through Windows Rights Management Services (RMS) or by using a Windows Live ID (formerly Microsoft .NET Passport) account.By default, when a user opens a rights-managed file created with a Windows Live ID, the application connects to a licensing server to verify the user''s credentials and to download a license that defines the level of access the user has to the file. If your organization has policies that govern access to external services such as Windows Live ID, this capability could allow users to violate those policies. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2007 system \ Manage Restricted Permissions ?Disable Microsoft Passport service for content with restricted permission? will be set to ?Enabled?.''Note: Group Policy Administrative Templates are available from the www.microsoft.com download site. The MS Office 2007 System (Office12.adm) is included in the AdminTemplates.exe file. This template provides themechanisms to incorporate Microsoft Office 2007 System policies via the Microsoft Group Policy Editor (gpedit.msc).''''Note: If the Microsoft Group Policy Editor (gpedit.msc) is not used to incorporate the remediation to this vulnerability the Microsoft Registry Editor (regedit.exe) may be used to create the registry key and value required.''"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM', 'DisablePassportCertification')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM', ('DisablePassportCertification=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\Common\DRM' -name 'DisablePassportCertification' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07OS0018"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"