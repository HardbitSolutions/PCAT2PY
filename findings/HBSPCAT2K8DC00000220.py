
#!/usr/bin/python
################################################################################
# V3383
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
        return r"V-3383"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system is not configured to use FIPS compliant Algorithms for Encryption, Hashing, and Signing."

    def get_vulnerability_discussion(self):
        return r"This setting ensures that the system uses algorithms that are FIPS compliant for encryption, hashing, and signing.  FIPS compliant algorithms meet specific standards established by the U.S. Government and should be the algorithms used for all OS encryption functions. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy', 'Enabled')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy', ('Enabled=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Lsa'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' -name 'Enabled' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312(a)(2)(iv),164.312(e)(2)(ii)"
    
    def get_pci(self):
        return "8.3,8.5,4.1,3.6,2.3"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000220"
    
    def get_dod8500_2(self):
        return "ECCT-1, ECCT-2"

    def get_800_53(self):
        return "AC-17(2),AC-18(1),SC-9,SC-9(1),SC-13,SC-13(1)"
    
    def get_iso_27001(self):
        return "A.10.6.1, A.10.8.1, A.10.8.5, A.11.4.1, A.11.4.2, A.11.4.6,  A.11.7.1, A.11.7.2, A.10.9.1, A.10.9.2, A.15.1.6"