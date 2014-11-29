
#!/usr/bin/python
################################################################################
# V1070
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
        return r"V-1070"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Server systems must be located in a controlled access area, accessible only to authorized personnel."

    def get_vulnerability_discussion(self):
        return r"Inadequate physical protection can undermine all other security precautions utilized to protect the system. This can jeopardize the confidentiality, availability, and integrity of the system.  Physical security of the AIS is the first line protection of any system. Relocate equipment to a controlled access area."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return "164.310(a)(1),164.310(a)(2)(iii)"
    
    def get_pci(self):
        return "9.1"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000001"
    
    def get_dod8500_2(self):
        return "PECF-1"

    def get_800_53(self):
        return "PE-2, PE-2(1), PE-7"
    
    def get_iso_27001(self):
        return "A.8.3.3, A.9.1.2"