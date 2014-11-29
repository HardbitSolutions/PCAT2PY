
#!/usr/bin/python
################################################################################
# V8326
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
        return r"V-8326"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The directory server supporting (directly or indirectly) system access or resource authorization must run on a machine dedicated to that function."

    def get_vulnerability_discussion(self):
        return r"Executing application servers on the same host machine with a directory server may substantially weaken the security of the directory server.  Web or database server applications usually require the addition of many programs and accounts increasing the attack surface of the computer. Some applications require the addition of privileged accounts providing potential sources of compromise.  Some applications (such as MS Exchange) may require the use of network ports or services conflicting with the directory server.  In this case, non-standard ports might be selected and this could interfere with intrusion detection or prevention services. Remove additional roles or applications such as web, database, and email from the domain controller."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.1"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000450"
    
    def get_dod8500_2(self):
        return "DCSP-1"

    def get_800_53(self):
        return "SC-3"
    
    def get_iso_27001(self):
        return "A.10.4.2, A.10.9.2"