
#!/usr/bin/python
################################################################################
# V1137
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
        return r"V-1137"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"An Auditors group has not been created to restrict access to the Windows Event Logs."

    def get_vulnerability_discussion(self):
        return r"The Security Event Log contains information on security exceptions that occur on the system.  This data is critical for identifying security vulnerabilities and intrusions.  The Application and System logs can also contain information that is critical in assessing security events.  Therefore, these logs must be protected from unauthorized access and modification.  An Auditors group will be used to restrict access to auditing through the User Right ?Manage auditing and security log?  and for assigning permissions to event logs. Only individuals who have auditing responsibilities (IAO, IAM, auditors, etc.) should be members of this group.The individual System Administrators responsible for maintaining this system can also be members of this group. Create an Auditors group for controlling the Windows Event Logs and assign the necessary rights and access controls."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "10.5"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000048"
    
    def get_dod8500_2(self):
        return "ECTP-1"

    def get_800_53(self):
        return "AU-9"
    
    def get_iso_27001(self):
        return "A.10.10.3, A.13.2.3, A.15.1.3, A.15.3.2"