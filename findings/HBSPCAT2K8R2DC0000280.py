
#!/usr/bin/python
################################################################################
# V27109
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
        return r"V-27109"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Access Control permissions on the FRS Directory data files must have proper access permissions."

    def get_vulnerability_discussion(self):
        return r"Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete directory data. Change the access control permissions on the directory data files to conform to the following guidance: Windows Permissions:Administrators, CREATOR OWNER, SYSTEM             : Full Control (F)[Directory server owner account\group]             : Full Control (F)[Directory server execution account\group]             : Full Control (F)[Other directory server group]                   : Read & Execute (R)[IAO-approved users \ user groups]                   : Read & Execute (R)UNIX Permissions:root                               : Read\Write\Exec (7)[Directory server owner account\group]             : Read\Write\Exec (7)[Directory server execution account\group]             : Read\Write\Exec (7)[Other directory server group]                   : Read\Exec (5)[IAO-approved users \ user groups]                   : Read\Exec (5)*Note: As far as possible, no (0) access is to be defined for the ?group? and\or ?other? permissions on UNIX directories or files containing sensitive data and directory backup files."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000280"
    
    def get_dod8500_2(self):
        return ""

    def get_800_53(self):
        return ""
    
    def get_iso_27001(self):
        return ""