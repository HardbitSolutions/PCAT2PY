
#!/usr/bin/python
################################################################################
# V3491
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
        return r"V-3491"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Audit logs will be reviewed on a daily basis."

    def get_vulnerability_discussion(self):
        return r"To be of value, audit logs from servers and other critical systems will be reviewed on a daily basis to identify security breaches and potential weaknesses in the security structure.  This can be done with the use of monitoring software or other utilities for this purpose. Create a site policy that mandates review of audit logs."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return "164.312(b)"
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000308"
    
    def get_dod8500_2(self):
        return "ECAT-1, ECAT-2"

    def get_800_53(self):
        return "AU-6, AU-6(1), AU-6(3), AU-12, IR-4(5), SI-4(12)"
    
    def get_iso_27001(self):
        return "A.10.10.2, A.10.10.5, A.13.1.1, A.15.1.5, A.10.10.1, A.10.10.4, A.6.1.2, A.6.1.6, A.13.2.1, A.13.2.2, A.13.2.3, A.10.9.3, A.10.10.3, A.15.3.1"