
#!/usr/bin/python
################################################################################
# V3377
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
        return r"V-3377"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system is configured to give anonymous users Everyone rights."

    def get_vulnerability_discussion(self):
        return r"This setting helps define the permissions that anonymous users have.  If this setting is enabled then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users should not have these permissions or rights. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Network access: Let everyone permissions apply to anonymous users? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Control\Lsa', 'EveryoneIncludesAnonymous')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\Lsa', ('EveryoneIncludesAnonymous=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Lsa'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa' -name 'EveryoneIncludesAnonymous' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000196"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2, ECLP-1, ECSC-1"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4), AC-5, AC-6, AC-6(2),CM-6"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3, A.10.1.3, A.11.4.1, A.11.4.4, A.10.10.2"