
#!/usr/bin/python
################################################################################
# V25884
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
        return r"V-25884"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The most current Office 2007 service pack is not installed."

    def get_vulnerability_discussion(self):
        return r"Failure to install the most current Office service pack leaves a system vulnerable to exploitation.  Current service packs correct known security and system vulnerabilities.  If Microsoft Office installation is not at most current service pack this is a Category II finding. If Microsoft Office installation is at an unsupported service pack this will be upgraded to a Category I finding since new vulnerabilities may not be patched. Install the most current Office 2007 service pack."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Office2007OfficeSystem"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07OS0035"
    
    def get_dod8500_2(self):
        return "VIVM-1"

    def get_800_53(self):
        return "RA-5, SI-2, SI-5"
    
    def get_iso_27001(self):
        return "A.12.6.1, A.15.2.2, A.13.1.2, A.6.1.6, A.6.1.7, A.10.4.1, A.10.9.3"