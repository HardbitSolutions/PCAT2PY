
#!/usr/bin/python
################################################################################
# V17741
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
        return r"V-17741"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Automation Security to enforce macro level security in Office documents must be configured."

    def get_vulnerability_discussion(self):
        return r"When a separate program is used to launch Microsoft Office Excel, PowerPoint, or Word programmatically, any macros can run in the programmatically opened application without being blocked. This functionality could allow an attacker to use automation to run malicious code in Excel, PowerPoint, or Word. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2010\ Security Settings ?Automation Security? to ?Enabled (Use application macro security level)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\Common\Security', 'AutomationSecurity')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\Common\Security', ('AutomationSecurity=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\Common'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\Common\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\Common\Security' -name 'AutomationSecurity' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OS0023"
    
    def get_dod8500_2(self):
        return "ECPC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"