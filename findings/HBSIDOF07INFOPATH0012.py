
#!/usr/bin/python
################################################################################
# V17582
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
        return r"V-17582"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Enable the Restriction on adding custom code to InfoPath forms."

    def get_vulnerability_discussion(self):
        return r"By default, users can design new InfoPath 2007 forms that use custom code to add interactivity and other functionality to forms. Designers can add managed code written in C# and Visual Basic .NET, as well as scripts written in Jscript and VBScript. An inexperienced or malicious user could design a form with dangerous code that harms users'' computers or puts sensitive data at risk. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office InfoPath 2007 \ Restricted Features ?Custom code? will be set to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Designer\RestrictedFeatures', 'CodeAllowed')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Designer\RestrictedFeatures', ('CodeAllowed=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Designer'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Designer\RestrictedFeatures'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Designer\RestrictedFeatures' -name 'CodeAllowed' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07InfoPath0012"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"