
#!/usr/bin/python
################################################################################
# V17187
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
        return r"V-17187"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Trust Bar Notifications for unsigned application add-ins must be blocked."

    def get_vulnerability_discussion(self):
        return r"If an application is configured to require all add-ins be signed by a trusted publisher, any unsigned add-ins the application loads will be disabled and the application will display the Trust Bar at the top of the active window. The Trust Bar contains a message informing users about the unsigned add-in. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Access 2010 \ Application Settings \ Security \ Trust Center ?Disable Trust Bar Notification for unsigned application add-ins and block them? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\access\security', 'NoTBPromptUnsignedAddin')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\access\security', ('NoTBPromptUnsignedAddin=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\access'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\access\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\access\security' -name 'NoTBPromptUnsignedAddin' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010Access"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10Access0006"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"