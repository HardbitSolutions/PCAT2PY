
#!/usr/bin/python
################################################################################
# V1135
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1135"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Non-administrative user accounts or groups will only have print permissions of Printer Shares."

    def get_vulnerability_discussion(self):
        return r"Improperly configured share permissions on printers can permit the addition of unauthorized print devices on the network.  Windows shares are a means by which files, folders, printers, and other resources can be published for network users to remotely access.  Regular users cannot create shares on their local machines; only Administrators and Power Users have that ability. Set the permissions on locally shared printers to meet the minimum requirements."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win7"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCATWIN7000038"
    
    def get_dod8500_2(self):
        return "ECCD-1"

    def get_800_53(self):
        return "AC-3"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"