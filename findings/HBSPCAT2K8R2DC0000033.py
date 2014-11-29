
#!/usr/bin/python
################################################################################
# V1127
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
        return "CAT I"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1127"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Only administrators responsible for the system must have Administrator rights on the system."

    def get_vulnerability_discussion(self):
        return r"An account that does not have Administrator duties must not have Administrator rights. Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.System administrators must log on to systems only using accounts with the minimum level of authority necessary. Standard user accounts must not be members of the built-in Administrators group. Set the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.Remove any standard user accounts."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312(a)(2)(i),164.312(a)(2)(ii)"
    
    def get_pci(self):
        return "7.1.1"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000033"
    
    def get_dod8500_2(self):
        return "ECPA-1"

    def get_800_53(self):
        return "AC-2(7)"
    
    def get_iso_27001(self):
        return "A.8.3.3, A.11.2.1, A.11.2.2, A.11.2.4, A.11.5.2, A.11.5.5, A.11.5.6"