
#!/usr/bin/python
################################################################################
# V36671
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
        return r"V-36671"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Audit data must be retained for at least one year.  If system contains sources and methods intelligence (SAMI), audit data must be retained for at least five years."

    def get_vulnerability_discussion(self):
        return r"Audit records are essential for investigating system activity after the fact. Retention periods for audit data are determined based on the sensitivity of the data handled by the system. Establish a policy that will ensure the retention of audit data for at least one year generally, and SAMI audit data for at least five years.  Ensure the audit retention policy is implemented."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312(b),164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000302"
    
    def get_dod8500_2(self):
        return "ECRR-1"

    def get_800_53(self):
        return "AU-11"
    
    def get_iso_27001(self):
        return "A.10.10.1, A.13.2.3, A.15.1.3"