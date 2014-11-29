
#!/usr/bin/python
################################################################################
# V36736
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
        return r"V-36736"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes."

    def get_vulnerability_discussion(self):
        return r"Failure to verify a certificate''s revocation status can result in the system accepting a revoked, and therefore unauthorized, certificate.  This could result in the installation of unauthorized software or a connection for rogue networks, depending on the use for which the certificate is intended.   Querying for certificate revocation mitigates the risk that the system will accept an unauthorized certificate. Install software that  provides certificate validation and revocation checking."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000371"
    
    def get_dod8500_2(self):
        return "IATS-1, IATS-2"

    def get_800_53(self):
        return "IA-5(2),SC-12(4), SC-12(5)"
    
    def get_iso_27001(self):
        return "A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.1, A.11.5.2, A.11.5.3, A.12.3.2"