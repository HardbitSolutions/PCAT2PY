
#!/usr/bin/python
################################################################################
# V36735
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
        return r"V-36735"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system must support automated patch management tools to facilitate flaw remediation to organization defined information system components."

    def get_vulnerability_discussion(self):
        return r"The organization (including any contractor to the organization) must promptly install security-relevant software updates (e.g., patches, service packs, hot fixes).  Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed. Establish a process to automatically install security-related software updates."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(A)"
    
    def get_pci(self):
        return "6.1"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000389"
    
    def get_dod8500_2(self):
        return "VIVM-1"

    def get_800_53(self):
        return "CA-7(2), RA-5, SI-2, SI-5"
    
    def get_iso_27001(self):
        return "A.6.1.8, A.12.6.1, A.13.1.2, A.15.2.1, A.15.2.2, A.6.1.6, A.6.1.7, A.10.4.1, A.10.9.3"