
#!/usr/bin/python
################################################################################
# V3828
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MANUAL finding
#
# 09/30/2014 Original Construction
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
        return r"V-3828"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Security-related Software Patches are not applied."

    def get_vulnerability_discussion(self):
        return r"Major software vendors release security patches and hot fixes to their products when security vulnerabilities are discovered.  It is essential that these updates be applied in a timely manner to prevent unauthorized persons from exploiting identified vulnerabilities.The Severity code may be elevated to a Category I if patches deemed Critical have not been applied. Apply all Microsoft security-related patches to the Windows system."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(B)"
    
    def get_pci(self):
        return "6.1"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000153"
    
    def get_dod8500_2(self):
        return "VIVM-1"

    def get_800_53(self):
        return "CA-7(2), RA-5, SI-2, SI-5"
    
    def get_iso_27001(self):
        return "A.6.1.8, A.12.6.1, A.13.1.2, A.15.2.1, A.15.2.2, A.6.1.6, A.6.1.7, A.10.4.1, A.10.9.3"