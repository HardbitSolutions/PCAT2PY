
#!/usr/bin/python
################################################################################
# V36662
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
        return r"V-36662"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization."

    def get_vulnerability_discussion(self):
        return r"Setting application accounts to expire may cause applications to stop functioning.  However, not changing them on a regular basis  exposes them to attack. Change application/service account passwords that are manually managed and entered by a system administrator at least annually or whenever an administrator with knowledge of the password leaves the organization."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000324"
    
    def get_dod8500_2(self):
        return "IAIA-1"

    def get_800_53(self):
        return "IA-2, IA-4(2), IA-5, IA-5(1), IA-5(3), IA-5(5), IA-5(6), IA-5(7)"
    
    def get_iso_27001(self):
        return "A.10.9.1, A.10.9.2, A.11.4.2, A.11.5.1, A.11.5.2 ,A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.3"