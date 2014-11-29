
#!/usr/bin/python
################################################################################
# V15579
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
        return r"V-15579"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Crash Detection management must be enforced."

    def get_vulnerability_discussion(self):
        return r"The ''Turn off Crash Detection'' policy setting allows you to manage the crash detection feature of add-on management in Internet Explorer. A crash report could contain sensitive information from the computer''s memory. If you enable this policy setting, a crash in Internet Explorer will be similar to one on a computer running Windows XP Professional Service Pack 1 and earlier, where Windows Error Reporting will be invoked. If you disable this policy setting, the crash detection feature in add-on management will be functional. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> ''Turn off Crash Detection'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions', 'NoCrashDetection')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions', ('NoCrashDetection=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions' -name 'NoCrashDetection' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE10"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIETen000102"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"