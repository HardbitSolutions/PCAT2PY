
#!/usr/bin/python
################################################################################
# V17668
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
        return r"V-17668"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"InfoPath 2003 forms as email forms in InfoPath 2013 must be disallowed."

    def get_vulnerability_discussion(self):
        return r"An attacker might target InfoPath 2003 forms to try and compromise an organization''s security. InfoPath 2003 did not write a published location for email forms, which means forms could open without a corresponding published location.By default, InfoPath sends all forms via email using InfoPath email forms integration, including forms created using the InfoPath 2003 file format. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft InfoPath 2013 \ InfoPath e-mail forms ''Disable sending InfoPath 2003 Forms as e-mail forms'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath', 'DisableInfoPath2003EmailForms')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath', ('DisableInfoPath2003EmailForms=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath' -name 'DisableInfoPath2003EmailForms' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Info0013"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"