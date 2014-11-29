
#!/usr/bin/python
################################################################################
# V32282A
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
        return "CAT I"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-32282A"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Standard user accounts must only have Read permissions to the Active Setup\Installed Components registry key."

    def get_vulnerability_discussion(self):
        return r"Permissions on the Active Setup\Installed Components registry key must only allow privileged accounts to add or change registry values.  If standard user accounts have this capability there is a potential for programs to run with elevated privileges when a privileged user logs on to the system. Ensure only Read permissions are assigned to standard user accounts and groups for the following registry keys.  The default configuration satisfies this requirement.All systemsHKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components64-bit systemsHKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000180"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"