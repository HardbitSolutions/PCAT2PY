
#!/usr/bin/python
################################################################################
# V3472
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
        return r"V-3472"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"If the time service is configured, it must use an authorized time server."

    def get_vulnerability_discussion(self):
        return r"The Windows Time Service controls time synchronization settings.  Time synchronization is essential for authentication and auditing purposes.  If the Windows Time Service is used, it must synchronize with a secure, authorized time source.   Domain-joined systems are automatically configured to synchronize with domain controllers.  If an NTP server is configured, it must synchronize with a secure, authorized time source. If the system needs to be configured to an NTP server, Set the system to point to an authorized time server by setting the policy value for Computer Configuration \ Administrative Templates \ System \ Windows Time Service \ Time Providers \ ''Configure Windows NTP Client'' to ''Enabled'', and Set the ''NtpServer'' field to point to an authorized time server."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "10.4"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000280"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"