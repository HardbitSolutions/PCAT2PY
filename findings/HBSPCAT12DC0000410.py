
#!/usr/bin/python
################################################################################
# V40173
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
        return r"V-40173"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"System-related documentation must be backed up per organization defined frequency consistent with recovery time and recovery point objectives."

    def get_vulnerability_discussion(self):
        return r"Operating system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. Backups shall be consistent with organizational recovery time and recovery point objectives. Back up system-related documentation per organization defined frequency to support recovery time and recovery point objectives."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.308(a)(7)(ii)(A),164.310(d)(2)(iv),164.312(c)(1)"
    
    def get_pci(self):
        return "3.1"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000410"
    
    def get_dod8500_2(self):
        return "CODB-1"

    def get_800_53(self):
        return "CP-9"
    
    def get_iso_27001(self):
        return "A.10.5.1, A.14.1.3, A.15.1.3"