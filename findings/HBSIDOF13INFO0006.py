
#!/usr/bin/python
################################################################################
# V17654
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
        return r"V-17654"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable dynamic caching of the form template in InfoPath eMail forms."

    def get_vulnerability_discussion(self):
        return r"By default, InfoPath 2007 caches form templates when they are attached to a mail item that is recognized as an InfoPath e-mail form. When users fill out forms that open with a restricted security level, InfoPath uses the cached version of the mailed template, rather than any published version.To circumvent users filling out a published form, an attacker could e-mail an alternate version of the form, which would return the data to the sender as part of a phishing attack and could be used to gain access to confidential information. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft InfoPath 2013 \ InfoPath e-mail forms ''Disable dynamic caching of the form template in InfoPath e-mail forms'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\deployment', 'CacheMailXSN')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\deployment', ('CacheMailXSN=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\deployment'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\deployment' -name 'CacheMailXSN' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Info0006"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"