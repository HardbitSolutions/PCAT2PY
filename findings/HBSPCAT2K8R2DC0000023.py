
#!/usr/bin/python
################################################################################
# V1112
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1112"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Outdated or unused accounts will be removed from the system."

    def get_vulnerability_discussion(self):
        return r"Outdated or unused accounts, provide penetration points that may go undetected. Regularly review accounts to determine if they are still active.  Accounts that have not been used in the last 35 days should either be removed or disabled."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.308(a)(3)(ii)(B),164.308(a)(4)(i),164.308(a)(4)(ii)(B),164.308(a)(4)(ii)(C),164.308(a)(3)(ii)(C)"
    
    def get_pci(self):
        return "7.1.2,7.1.4,8.1.3"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000023"
    
    def get_dod8500_2(self):
        return "IAAC-1"

    def get_800_53(self):
        return "AC-2, PS-4, PS-5"
    
    def get_iso_27001(self):
        return "A.8.3.3, A.11.2.1, A.11.2.2, A.11.2.4, A.11.5.2, A.11.5.5, A.11.5.6, A.8.3.1, A.8.3.2, A.8.3.3"