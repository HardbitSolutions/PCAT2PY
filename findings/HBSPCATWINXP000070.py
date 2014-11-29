
#!/usr/bin/python
################################################################################
# V1168
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
        return r"V-1168"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Members of the Backup Operators group do not have separate accounts for backup duties and normal operational tasks."

    def get_vulnerability_discussion(self):
        return r"Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to cirvumvent the file access restrictions present on NTFS disk drives for the purpose of backup and restore.  Members of the Backup Operators group should have special logon accounts for performing their backup duties. Create the necessary documentation that identifies the members of this privileged group.  Ensure each member has a separate account for user duties and one for his privileged duties."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000070"
    
    def get_dod8500_2(self):
        return "ECLP-1"

    def get_800_53(self):
        return "AC-5, AC-6, AC-6(2)"
    
    def get_iso_27001(self):
        return "A.10.1.3, A.11.2.2, A.11.4.1, A.11.4.4, A.11.5.4, A.11.6.1, A.12.4.3"