
#!/usr/bin/python
################################################################################
# V26708
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
        return r"V-26708"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Publisher Automation Security Level must be configured for high security."

    def get_vulnerability_discussion(self):
        return r"When a separate application is used to launch Publisher 2013 programmatically, any macros can run in the programmatically-opened application without being blocked.  Disabling or not configuring this setting could allow a malicious user to use automation to run malicious code in Publisher 2013. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Publisher 2013 \ Security ''Publisher Automation Security Level'' to ''Enabled and High (Disabled)'' is selected."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\Common\Security', 'AutomationSecurityPublisher')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\Common\Security', ('AutomationSecurityPublisher=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\Common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\Common\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\Common\Security' -name 'AutomationSecurityPublisher' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Publisher"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Pub0012"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"