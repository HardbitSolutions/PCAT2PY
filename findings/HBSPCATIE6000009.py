
#!/usr/bin/python
################################################################################
# V6234
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
        return r"V-6234"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The IE third party cookies parameter is not set correctly."

    def get_vulnerability_discussion(self):
        return r"This parameter ensures that third party cookies are blocked.  Third party cookies come from a site other than the site being browsed. Since these cross sites, the storing unwanted data or allowing data to be retrieved later via the cookie is of greater concern for malicious activity. Manipulate third party cookies to blocked."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "IE6"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE6000009"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"