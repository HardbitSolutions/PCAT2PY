
#!/usr/bin/python
################################################################################
# V4107
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
        return r"V-4107"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Windows operating systems that are no longer supported by the vendor for security updates must not be installed on a system."

    def get_vulnerability_discussion(self):
        return r"Windows operating systems that are no longer supported by Microsoft for security updates are not evaluated or updated for vulnerabilities leaving them open to potential attack.  Prior to the end of support, organizations must plan for the transition to a supported operating system to ensure continued support and availability. At least 6 months prior to the end of support, develop a migration plan to move systems to a supported operating system.  Upgrade systems to a supported operating system prior to the end of support on 8 April 2014."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "XP"

    def get_hippa(self):
        return "164.312(c)(1),164.314(a)(2)(i)"
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATWINXP000192"
    
    def get_dod8500_2(self):
        return "DCSQ-1"

    def get_800_53(self):
        return "SA-4(3),SA-11(1)"
    
    def get_iso_27001(self):
        return "A.10.3.2, A.12.1.1, A.12.5.5, A.6.1.8, A.13.1.2"