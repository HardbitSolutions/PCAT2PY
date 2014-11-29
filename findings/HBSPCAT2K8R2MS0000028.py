
#!/usr/bin/python
################################################################################
# V1120
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
        return r"V-1120"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Installed FTP server will not be configured to allow prohibited logins."

    def get_vulnerability_discussion(self):
        return r"The FTP (File Transfer Protocol) service allows remote users to access shared files and directories.  Allowing anonymous FTP makes user auditing difficult.Using accounts that have administrator privileges to log on to FTP risks that the user id and password will be captured on the network, and give administrator access to an unauthorized user. Set the system to prevent an installed FTP service from allowing prohibited logons."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000028"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"