
#!/usr/bin/python
################################################################################
# V40237
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
        return r"V-40237"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The US DoD CCEB Interoperability Root CA 1 to DoD Root CA 2 cross-certificate must be installed into the Untrusted Certificates Store."

    def get_vulnerability_discussion(self):
        return r"To ensure users do not experience denial of service on NIPRNet when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CA 2, the US DoD CCEB Interoperability Root CA 1 to DoD Root CA 2 cross-certificate must be installed in the Untrusted Certificate Store.  This requirement only applies to NIPRNet systems. Install the US DoD CCEB Interoperability Root CA 1 to DoD Root CA 2 cross-certificate on NIPRNet systems only.  Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.  The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000322"
    
    def get_dod8500_2(self):
        return "IATS-1, IATS-2"

    def get_800_53(self):
        return "IA-5(2),SC-12(4), SC-12(5)"
    
    def get_iso_27001(self):
        return "A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.1, A.11.5.2, A.11.5.3, A.12.3.2"