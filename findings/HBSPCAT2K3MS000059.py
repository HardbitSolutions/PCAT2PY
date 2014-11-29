
#!/usr/bin/python
################################################################################
# V1155
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
        return r"V-1155"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access."

    def get_vulnerability_discussion(self):
        return r"Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.The ''Deny Access from the Network'' right defines the accounts that are prevented from logging on from the network.  Groups must be assigned this right to prevent unauthenticated access. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ User Rights Assignment \ ''Deny access to this computer from the network'' to include the following.Domain Systems Only:Enterprise Admins GroupDomain Admins Group*All Local Administrator AccountsAll Systems:Guests GroupAnonymous LogonSupport_388945a0*Note: Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000059"
    
    def get_dod8500_2(self):
        return "ECLP-1"

    def get_800_53(self):
        return "AC-5, AC-6, AC-6(2)"
    
    def get_iso_27001(self):
        return "A.10.1.3, A.11.2.2, A.11.4.1, A.11.4.4, A.11.5.4, A.11.6.1, A.12.4.3"