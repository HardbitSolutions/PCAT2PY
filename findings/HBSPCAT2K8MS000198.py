
#!/usr/bin/python
################################################################################
# V3379
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
        return "CAT I"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-3379"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system is configured to store the LAN Manager hash of the password in the SAM."

    def get_vulnerability_discussion(self):
        return r"This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.  The LAN Manager hash is a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Network security: Do not store LAN Manager hash value on next password change? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Control\Lsa', 'NoLMHash')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\Lsa', ('NoLMHash=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Lsa'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa' -name 'NoLMHash' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(D),164.312(d),164.312(a)(2)(i)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000198"
    
    def get_dod8500_2(self):
        return "ECSC-1, IAIA-1, IAIA-2"

    def get_800_53(self):
        return "CM-6,  IA-2, IA-4(2), IA-5, IA-5(1), IA-5(3), IA-5(5), IA-5(6), IA-5(7), IA-4(3), IA-5(4)"
    
    def get_iso_27001(self):
        return "A.10.10.2, A.10.9.1, A.10.9.2, A.11.4.2, A.11.5.1, A.11.5.2, A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.3"