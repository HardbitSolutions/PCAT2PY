
#!/usr/bin/python
################################################################################
# V40193
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
        return r"V-40193"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Virtual guest operating systems must be registered in a vulnerability and asset management system."

    def get_vulnerability_discussion(self):
        return r"Virtual guest operating systems share the same vulnerabilities as operating systems running on dedicated hardware and must be individually assessed for security guidance compliance.  The VMS used may be DISA VMS or a similar vulnerability and asset management system. Register all virtual guest operating systems as separate assets in a vulnerability and asset management system."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000386"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"