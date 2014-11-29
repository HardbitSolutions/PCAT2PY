
#!/usr/bin/python
################################################################################
# V1077C
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
        return r"V-1077C"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"ACLs for event logs do not conform to minimum requirements."

    def get_vulnerability_discussion(self):
        return r"Event logs are susceptible to unauthorized, and possibly anonymous, tampering if proper ACLs are not applied. Set the ACL permissions on the event logs as defined."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win7"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "10.5"
    
    def get_hbs_id(self):
        return "HBSPCATWIN7000009"
    
    def get_dod8500_2(self):
        return "ECTP-1"

    def get_800_53(self):
        return "AU-9"
    
    def get_iso_27001(self):
        return "A.10.10.3, A.13.2.3, A.15.1.3, A.15.3.2"