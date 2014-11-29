
#!/usr/bin/python
################################################################################
# V14224
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
        return r"V-14224"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system will have a backup administrator account."

    def get_vulnerability_discussion(self):
        return r"This check verifies that a backup administrator account has been created to ensure system availability in the event that no administrators are able or available to access the system.  The built-in administrator account may be used for this purpose.  The IAO will ensure the backup administrator account is stored in a secure location. Create and maintain a backup administrator account for emergency situations."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.312(a)(2)(i),164.312(a)(2)(ii)"
    
    def get_pci(self):
        return "7.1.1"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000073"
    
    def get_dod8500_2(self):
        return "ECPA-1"

    def get_800_53(self):
        return "AC-2(7)"
    
    def get_iso_27001(self):
        return "A.8.3.3, A.11.2.1, A.11.2.2, A.11.2.4, A.11.5.2, A.11.5.5, A.11.5.6"