
#!/usr/bin/python
################################################################################
# V26359
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
        return r"V-26359"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Windows dialog box title for the legal banner will be configured."

    def get_vulnerability_discussion(self):
        return r"Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options\Interactive Logon: Message title for users attempting to log on to an Approved Notice and Consent Banner."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(A)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000206"
    
    def get_dod8500_2(self):
        return "ECWM-1"

    def get_800_53(self):
        return "AC-8"
    
    def get_iso_27001(self):
        return "A.6.2.2, A.11.5.1, A.15.1.5"