
#!/usr/bin/python
################################################################################
# V1148
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
        return r"V-1148"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Local users must not exist on a system in a domain."

    def get_vulnerability_discussion(self):
        return r"To minimize potential points of attack, local users, other than built-in accounts such as Administrator and Guest accounts, must not exist on a workstation in a domain.  Users must log onto workstations in a domain with their domain accounts. Configure domain-joined systems to restrict the existence of local user accounts.  Remove any unauthorized local accounts."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.308(a)(3)(ii)(B),164.308(a)(4)(i),164.308(a)(4)(ii)(B),164.308(a)(4)(ii)(C),164.308(a)(3)(ii)(C)"
    
    def get_pci(self):
        return "7.1.2,7.1.4,8.1.3"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000034"
    
    def get_dod8500_2(self):
        return "IAAC-1"

    def get_800_53(self):
        return "AC-2, PS-4, PS-5"
    
    def get_iso_27001(self):
        return "A.8.3.3, A.11.2.1, A.11.2.2, A.11.2.4, A.11.5.2, A.11.5.5, A.11.5.6, A.8.3.1, A.8.3.2, A.8.3.3"