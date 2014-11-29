
#!/usr/bin/python
################################################################################
# V17655
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
        return r"V-17655"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disabling of email forms from the Full Trust Security Zone must be configured."

    def get_vulnerability_discussion(self):
        return r"InfoPath provides three security levels for form templates: Restricted, Domain, and Full Trust. The security levels determine whether a form template can access data on other domains, or access files and settings on your computer. Fully trusted forms have a Full Trust security level, and can access files and settings on users'' computers. The form template for these forms must be digitally signed with a trusted root certificate, or installed on users'' computers.By default, InfoPath can open email forms with full trust. If an attacker designs and sends a dangerous fully trusted email form, it could affect users'' computers or give the attacker access to sensitive information. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft InfoPath 2013 \ InfoPath e-mail forms ''Disable e-mail forms from the Full Trust security zone'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security', 'EnableFullTrustEmailForms')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security', ('EnableFullTrustEmailForms=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security' -name 'EnableFullTrustEmailForms' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Info0007"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"