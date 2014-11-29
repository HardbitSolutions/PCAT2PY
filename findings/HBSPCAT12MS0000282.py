
#!/usr/bin/python
################################################################################
# V3289
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
        return r"V-3289"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Servers must have a host-based Intrusion Detection System."

    def get_vulnerability_discussion(self):
        return r"A properly configured host-based Intrusion Detection System provides another level of defense against unauthorized access to critical servers.  With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources. Install a host-based Intrusion Detection System on each server."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return "1.2,1.2.1,1.3.1,1.3.2,1.3.3,1.3.4,10.5.5,11.4,11.5"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000282"
    
    def get_dod8500_2(self):
        return "ECID-1"

    def get_800_53(self):
        return "SC-7(12), SI-4"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.4.2, A.10.6.1, A.10.8.1, A.10.8.4, A.10.9.1, A.10.9.2, A.10.10.2, A.11.4.1, A.11.4.5, A.11.4.6, A.11.4.7, A.11.6.2, A.10.9.3, A.10.10.3, A.15.3.1"