
#!/usr/bin/python
################################################################################
# V14783
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
        return r"V-14783"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Separate, NSA-approved (Type 1) cryptography must be used to protect the directory data-in-transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data."

    def get_vulnerability_discussion(self):
        return r"Commercial-grade encryption does not provide adequate protection when the classification level of directory data in transit is higher than the level of the network or when sources and methods intelligence (SAMI) data is included. Configure NSA-approved (Type 1) cryptography to protect the directory data in transit for directory service implementations at a classified confidentiality level that transfers replication data through a network cleared to a lower level than the data."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312(a)(2)(iv),164.312(e)(2)(ii)"
    
    def get_pci(self):
        return "8.3,8.5,4.1,3.6,2.3"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000104"
    
    def get_dod8500_2(self):
        return "ECCT-2, ECNK-2"

    def get_800_53(self):
        return "SC-9, SC-9(1), SC-13, SC-13(2),SC-13(3)"
    
    def get_iso_27001(self):
        return "A.10.9.1, A.10.9.2, A.15.1.6"