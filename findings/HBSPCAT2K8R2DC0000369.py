
#!/usr/bin/python
################################################################################
# V8316
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
        return r"V-8316"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Active Directory data files must have proper access control permissions."

    def get_vulnerability_discussion(self):
        return r"Improper access permissions for directory data related files could allow unauthorized users to read, modify, or delete directory data or audit trails. Verify the access on NTDS database and log files are maintained as follows.NT AUTHORITY\SYSTEM:(I)(F)BUILTIN\Administrators:(I)(F)(I) - permission inherited from parent container(F) - full access"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.2"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000369"
    
    def get_dod8500_2(self):
        return "ECAN-1, ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3,AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"