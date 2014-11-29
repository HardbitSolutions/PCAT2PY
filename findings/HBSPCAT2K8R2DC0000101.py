
#!/usr/bin/python
################################################################################
# V14820
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
        return r"V-14820"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Domain Controller PKI certificates must be issued by the DoD PKI or an approved External Certificate Authority (ECA)."

    def get_vulnerability_discussion(self):
        return r"A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementation is secure. Without proper practices, the certificates issued by a CA have limited value in authentication functions. The use of multiple CAs from separate PKI implementations results in interoperability issues. If servers and clients do not have a common set of root CA certificates, they are not able to authenticate each other. Obtain PKI certificates issued by the DoD PKI or an approved External Certificate Authority (ECA)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000101"
    
    def get_dod8500_2(self):
        return "IAKM-1, IAKM-2, IATS-1, IATS-2"

    def get_800_53(self):
        return "SC-12(2), SC-12(4),IA-5(2),SC-12(5)"
    
    def get_iso_27001(self):
        return "A.12.3.2, A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.1, A.11.5.2, A.11.5.3"