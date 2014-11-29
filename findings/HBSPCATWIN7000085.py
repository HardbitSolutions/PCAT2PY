
#!/usr/bin/python
################################################################################
# V14250B
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
        return r"V-14250B"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Automatic Updates must not be used (unless configured to point to an approved server)."

    def get_vulnerability_discussion(self):
        return r"Uncontrolled system updates can introduce issues to a system. The system must be configured to prevent Automatic Updates from being run unless directed to an Approved Windows Server Update Services (WSUS) server. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Windows Update \ ''Configure Automatic Updates'' to ''Disabled''. If the site is using an approved WSUS server to distribute software updates, the policy setting to Set the WSUS URL is Computer Configuration \ Administrative Templates \ Windows Components \ Windows Update \ ''Specify intranet Microsoft update service location''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win7"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN7000085"
    
    def get_dod8500_2(self):
        return "DCSL-1"

    def get_800_53(self):
        return "CM-5(6)"
    
    def get_iso_27001(self):
        return "A.10.1.2, A.12.4.1, A.12.4.3, A.12.5.3"