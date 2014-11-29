
#!/usr/bin/python
################################################################################
# V2371
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
        return r"V-2371"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"ACLs for disabled services do not conform to minimum standards."

    def get_vulnerability_discussion(self):
        return r"When configuring either the startup mode or access control list for a service, you must configure the other as well. When a service is explicitly disabled, its ACL should also be secured by changing the default ACL from Everyone Full Control to grant Administrators and SYSTEM Full Control and Interactive Read access. Create a Custom Security Template using the Security Template MMC Snap-in to set the permissions as required for disabled services.Import the Custom Template into the Security Configuration and Analysis Snap-In and Select Configure Computer NowOr import the Custom Template in to a Group Policy for application.The administrator should have a thorough understanding of these tools before implementing settings with them."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000122"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"