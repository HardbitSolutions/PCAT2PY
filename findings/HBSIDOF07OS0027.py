
#!/usr/bin/python
################################################################################
# V17750
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD NOT EXIST finding
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
        return r"V-17750"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable Load controls in forms3 - Office"

    def get_vulnerability_discussion(self):
        return r"ActiveX controls are Component Object Model (COM) objects and have unrestricted access to users'' computers. ActiveX controls can access the local file system and change the registry settings of the operating system. If a malicious user repurposes an ActiveX control to take over a user''s computer, the effect could be significant.To help improve security, ActiveX developers can mark controls as Safe For Initialization (SFI), which means that the developer states that the controls are safe to open and run and not capable of causing harm to any computers. If a control is not marked SFI, the control could adversely affect a computer?or it''s possible the developers did not test the control in all situations and are not sure whether their control might be compromised at some future date.SFI controls run in safe mode, which limits their access to the computer. For example, a worksheet control can both read and write files when it is in unsafe mode, but perhaps only read from files when it is in safe mode. This functionality allows the control to be used in very powerful ways when safety wasn''t important, but the control would still be safe for use in a Web page.If a control is not marked as SFI, it is marked Unsafe For Initialization (UFI), which means that it is capable of affecting a user''s computer. If UFI ActiveX controls are loaded, they are always loaded in unsafe mode.This setting allows administrators to control how ActiveX controls in UserForms should be initialized based upon whether they are SFI or UFI. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2007 system \ Security Settings ?Load Controls in Forms3? will be set to ?Diabled?.''Note: Group Policy Administrative Templates are available from the www.microsoft.com download site. The MS Office 2007 System (Office12.adm) is included in the AdminTemplates.exe file. This template provides themechanisms to incorporate Microsoft Office 2007 System policies via the Microsoft Group Policy Editor (gpedit.msc).''''Note: If the Microsoft Group Policy Editor (gpedit.msc) is not used to incorporate the remediation to this vulnerability the Microsoft Registry Editor (regedit.exe) may be used to create the registry key and value required.''"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\VBA\Security\LoadControlsInForms', '')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\VBA\Security\LoadControlsInForms', ('=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == -1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\VBA'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\VBA\Security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\VBA\Security\LoadControlsInForms'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\VBA\Security\LoadControlsInForms' -name '' -value -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07OS0027"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"