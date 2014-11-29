
#!/usr/bin/python
################################################################################
# V1073
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
        return r"V-1073"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Systems must be at supported service pack (SP) or release levels."

    def get_vulnerability_discussion(self):
        return r"Systems at unsupported service packs or releases will not receive security updates for new vulnerabilities and leaves them subject to exploitation.  Systems must be maintained at a service pack level supported by the vendor with new security updates. Update the system to a supported service pack.Application of new service packs should be thoroughly tested before deploying in a production environment."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(A)"
    
    def get_pci(self):
        return "6.1"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000003"
    
    def get_dod8500_2(self):
        return "VIVM-1"

    def get_800_53(self):
        return "CA-7(2), RA-5, SI-2, SI-5"
    
    def get_iso_27001(self):
        return "A.6.1.8, A.12.6.1, A.13.1.2, A.15.2.1, A.15.2.2, A.6.1.6, A.6.1.7, A.10.4.1, A.10.9.3"