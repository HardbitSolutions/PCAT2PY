
#!/usr/bin/python
################################################################################
# V26697
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
        return r"V-26697"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The InfoPath APTCA Assembly Allowable List must be enforced."

    def get_vulnerability_discussion(self):
        return r"InfoPath 2013 forms'' business logic can only call into Global Assembly Cache (GAC) assemblies listed in the APTCA Assembly Allowable List. If this configuration is changed, forms can call into any assembly in the GAC where the Allow Partially Trusted Callers Attribute (APTCA) is set. This configuration could allow malicious developers to access assemblies in the GAC not intended to be used by InfoPath forms. Set the policy value for: Computer Configuration \ Administrative Templates \ Microsoft InfoPath 2013 (Machine) \ Security ''InfoPath APTCA Assembly Allowable List Enforcement'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\office\15.0\InfoPath\security', 'APTCA_AllowList')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\office\15.0\InfoPath\security', ('APTCA_AllowList=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\office\15.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\office\15.0\InfoPath\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\office\15.0\InfoPath\security' -name 'APTCA_AllowList' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Info0024"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"