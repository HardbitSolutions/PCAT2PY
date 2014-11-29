
#!/usr/bin/python
################################################################################
# V8317
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
        return r"V-8317"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Data files owned by users must be on a different logical partition from the directory server data files."

    def get_vulnerability_discussion(self):
        return r"When directory service data files, especially for directories used for identification, authentication, or authorization, reside on the same logical partition as user-owned files, the directory service data may be more vulnerable to unauthorized access or other availability compromises.  Directory service and user-owned data files sharing a partition may be configured with less restrictive permissions in order to allow access to the user data. The directory service may be vulnerable to a denial of service attack when user-owned files on a common partition are expanded to an extent preventing the directory service from acquiring more space for directory or audit data. Verify files owned by users  are stored on a different logical partition then the directory server data files."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.1"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000446"
    
    def get_dod8500_2(self):
        return "DCSP-1"

    def get_800_53(self):
        return "SC-3"
    
    def get_iso_27001(self):
        return "A.10.4.2, A.10.9.2"