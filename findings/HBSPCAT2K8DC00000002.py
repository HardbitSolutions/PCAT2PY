
#!/usr/bin/python
################################################################################
# V1072
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
        return r"V-1072"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Shared user accounts are permitted on the system."

    def get_vulnerability_discussion(self):
        return r"Shared accounts (accounts where two or more people log in with the same user identification) do not provide adequate identification and authentication.  There is no way to provide for nonrepudiation or individual accountability for system access and resource usage. Remove any shared accounts that do not meet the exception requirements listed."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312(a)(2)(i)"
    
    def get_pci(self):
        return "8.5"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000002"
    
    def get_dod8500_2(self):
        return "IAGA-1"

    def get_800_53(self):
        return "IA-2(5)"
    
    def get_iso_27001(self):
        return "A.10.9.1, A.10.9.2, A.11.4.2, A.11.5.1, A.11.5.2"