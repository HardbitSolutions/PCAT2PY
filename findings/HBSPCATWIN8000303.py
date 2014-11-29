
#!/usr/bin/python
################################################################################
# V36672
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
        return r"V-36672"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Audit records must be backed up on an organization defined frequency onto a different system or media than the system being audited."

    def get_vulnerability_discussion(self):
        return r"Protection of log data includes assuring the log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on an organizational defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained. Establish and implement a process for backing up log data on an organization defined frequency to another system or media other than the system being audited."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312(b),164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000303"
    
    def get_dod8500_2(self):
        return "ECRR-1"

    def get_800_53(self):
        return "AU-11"
    
    def get_iso_27001(self):
        return "A.10.10.1, A.13.2.3, A.15.1.3"