
#!/usr/bin/python
################################################################################
# V14797
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-14797"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Anonymous access to the root DSE of a non-public directory must be disabled."

    def get_vulnerability_discussion(self):
        return r"Allowing anonymous access to the root DSE data on a directory server provides potential attackers with a number of details about the configuration and data contents of a directory. For example, the namingContexts attribute indicates the directory space contained in the directory; the supportedLDAPVersion attribute indicates which versions of the LDAP protocol the server supports; and the supportedSASLMechanisms attribute indicates the names of supported authentication mechanisms. An attacker with this information may be able to select more precisely targeted attack tools or higher value targets. Implement network protections to reduce the risk of anonymous access.Network hardware ports at the site are subject to 802.1x authentication or MAC address restrictions. Premise firewall or host restrictions prevent access to ports 389, 636, 3268, and 3269 from client hosts not explicitly identified."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.2"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000083"
    
    def get_dod8500_2(self):
        return "ECAN-1, ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3,AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"