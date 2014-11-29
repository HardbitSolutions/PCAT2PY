
#!/usr/bin/python
################################################################################
# V17658
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
        return r"V-17658"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disabling of Fully Trusted Solutions access to computers must be configured."

    def get_vulnerability_discussion(self):
        return r"InfoPath users can choose whether to allow trusted forms to run on their computers. The Full Trust security level allows a form to access local system resources, such as COM components or files on users'' computers, and suppresses certain security prompts. It can only be used with forms that are installed on users'' computers or with forms using a form template that is digitally signed with a trusted root certificate.As with any security model that allows trusted entities to operate with fewer security controls, if a form with malicious content is marked as fully trusted it could be used to compromise information security or affect users'' computers. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft InfoPath 2010 \ Security \ ?Disable fully trusted solutions full access to computer? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security', 'RunFullTrustSolutions')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security', ('RunFullTrustSolutions=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security' -name 'RunFullTrustSolutions' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10Info0011"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"