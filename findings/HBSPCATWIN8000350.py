
#!/usr/bin/python
################################################################################
# V36732
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
        return r"V-36732"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The TFTP Client must not be installed on the system."

    def get_vulnerability_discussion(self):
        return r"Some protocols and services do not support required security features, such as encrypting passwords or traffic. Uninstall ''TFTP Client'' from the system through ''Turn Windows Features on or off''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.2"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000350"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"