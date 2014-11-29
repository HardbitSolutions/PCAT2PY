
#!/usr/bin/python
################################################################################
# V14229
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated BINARY EQ finding
#
# 09/23/2014 Original Construction
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
        return r"V-14229"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Audit of Backup and Restore Privileges is not turned off."

    def get_vulnerability_discussion(self):
        return r"This policy setting stops the system from generating audit events for every file backed up or restored which could fill the Security log in Windows. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Audit: Audit the use of Backup and Restore privilege? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry BINARY
        binary = cli.get_reg_binary(r'HKLM:\System\CurrentControlSet\Control\Lsa', 'FullPrivilegeAuditing')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\Lsa', ('FullPrivilegeAuditing=')] + binary

        if self.__verbose:
            print self.__output

        if len(binary) == 1:
            if int(binary[0], 0) == 0:
                self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Lsa'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa' -name 'FullPrivilegeAuditing' -Type Binary -value 0")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000076"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"