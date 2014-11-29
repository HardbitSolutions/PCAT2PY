
#!/usr/bin/python
################################################################################
# V2375
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
        return r"V-2375"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Specified groups are not restricted."

    def get_vulnerability_discussion(self):
        return r"The Restricted Groups option allows the administrator to manage membership of sensitive groups.  The Power Users group is one such group.  This group has been given significant privileges under Windows 2000. Set the system to restrict membership of the Power Users group to have no accounts or groups as members."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000125"
    
    def get_dod8500_2(self):
        return "ECLP-1"

    def get_800_53(self):
        return "AC-5, AC-6, AC-6(2)"
    
    def get_iso_27001(self):
        return "A.10.1.3, A.11.2.2, A.11.4.1, A.11.4.4, A.11.5.4, A.11.6.1, A.12.4.3"