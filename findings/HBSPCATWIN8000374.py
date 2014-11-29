
#!/usr/bin/python
################################################################################
# V36757
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
        return r"V-36757"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Bluetooth must be turned off unless approved by the organization."

    def get_vulnerability_discussion(self):
        return r"If not configured properly, Bluetooth may allow rogue devices to communicate with a system.  If a rogue device is paired with a system, there is potential for sensitive information to be compromised. Turn off Bluetooth radios not organizationally approved.  Establish an organizational policy for the use of Bluetooth."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.310(b)"
    
    def get_pci(self):
        return "1.4,2.1.1,12.3.10"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000374"
    
    def get_dod8500_2(self):
        return "ECWN-1"

    def get_800_53(self):
        return "AC-18, AC-18(1), AC-18(2), AC-18(3), AC-18(4), AC-19"
    
    def get_iso_27001(self):
        return "A.10.6.1, A.10.8.1, A.11.4.1, A.11.4.2, A.11.4.6,  A.11.7.1, A.9.2.5, A.10.4.1, A.10.7.3, A.11.4.3"