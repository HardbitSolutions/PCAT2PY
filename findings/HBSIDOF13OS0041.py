
#!/usr/bin/python
################################################################################
# V40880
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
        return r"V-40880"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"When using the Office Feedback tool, the ability to include a screenshot must be disabled."

    def get_vulnerability_discussion(self):
        return r"The ''Office Feedback'' tool, also called ''Send-a-Smile'', allows a user to click on an icon and send feedback to Microsoft. The ''Office Feedback'' Tool must be configured to be disabled. In the event that the Office Feedback Tool has not been configured correctly as disabled, this policy configures whether the uploading of screenshots via the tool is allowed and should also be disabled. Uploading screenshots to a commercial vendor from a computer may unintentionally reveal configuration and/or FOUO content. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office 2013 \ Privacy \ Trust Center \ ''Allow including screenshot with Office Feedback'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\common\feedback', 'includescreenshot')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\common\feedback', ('includescreenshot=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\common'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\common\feedback'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\common\feedback' -name 'includescreenshot' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13OS0041"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"