
#!/usr/bin/python
################################################################################
# V6830
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
        return r"V-6830"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"DCOM calls are not executed under the security context of the calling user."

    def get_vulnerability_discussion(self):
        return r"DCOM calls are executed under the security context of the calling user by default.  If the RunAs key has been altered, the DCOM calls can be executed under the user context of the currently logged in user, or as a third user.  If present, the RunAs value tells the COM Service Control Manager (SCM) the name of the account under which the server is to be activated. In addition to the account name, the COM SCM must also have the password of the account. The result of a successful logon is a security context (token) for the named account that is used as the primary token for the new COM server process. Administrators should not use this method in the evaluated configuration if accountability is required, since accountability cannot be enforced. RunAs values will be removed. Remove any RunAs values from DCOM objects in the Registry."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000254"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"