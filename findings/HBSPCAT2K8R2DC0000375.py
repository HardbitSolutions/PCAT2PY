
#!/usr/bin/python
################################################################################
# V8327
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
        return r"V-8327"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Windows services that are critical for directory server operation must be configured for automatic startup."

    def get_vulnerability_discussion(self):
        return r"Active Directory (AD) is dependent on several Windows services. If one or more of these services is not configured for automatic startup, AD functions may be partially or completely unavailable until the services are manually started. This could result in a failure to replicate data or to support client authentication and authorization requests. Ensure the following services that are critical for directory server operation are configured for automatic startup.- Active Directory Domain Services- DFS Replication- DNS Client- DNS server- Group Policy Client- Intersite Messaging- Kerberos Key Distribution Center- NetLogon - Windows Time (not required if another time synchronization tool is implemented to start automatically)"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312(c)(1),164.312(c)(2),164.312(e)(2)(i)"
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000375"
    
    def get_dod8500_2(self):
        return "ECTM-1, ECTM-2"

    def get_800_53(self):
        return "SC-8, SC-8(2), SI-7,SC-16,SC-23"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3, A.10.10.2, A.12.2.2, A.12.2.3, A.12.4.1, A.10.6.1, A.10.8.1, A.10.8.4, A.10.9.1, A.10.9.2, A.7.2.2"