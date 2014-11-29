
#!/usr/bin/python
################################################################################
# V6850
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
        return r"V-6850"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Auditing records are configured as required."

    def get_vulnerability_discussion(self):
        return r"Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, analyze compromises that have occurred as well as detect an attack that has begun or is about to begin. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Without an audit trail that provides information as to event that occurred and if it was successful or unsuccessful, it is difficult to analyze a series of events to determine the steps used by an attacker to compromise a system or network, or what exactly happened that led to a denial of service. Collecting data such as the successful and unsuccessful events is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Set the system to audit categories as outlined in check procedure."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312(b)"
    
    def get_pci(self):
        return "10.3.4"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000214"
    
    def get_dod8500_2(self):
        return "ECAR-2, ECAR-3"

    def get_800_53(self):
        return "AU-2 ,AU-3,AU-8"
    
    def get_iso_27001(self):
        return "A.10.10.1, A.10.10.2, A.10.10.4, A.10.10.5, A.11.5.4, A.15.3.1, A.10.10.6, A.13.2.3"