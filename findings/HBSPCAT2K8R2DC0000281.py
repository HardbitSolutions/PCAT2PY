
#!/usr/bin/python
################################################################################
# V27119
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
        return r"V-27119"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Active Directory SYSVOL directory must have the proper access control permissions."

    def get_vulnerability_discussion(self):
        return r"Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete directory data.The SYSVOL directory contains public files (to the domain) such as policies and logon scripts.  Data in shared subdirectories are replicated to all domain controllers in a domain. Verify the access on SYSVOL directory do not allow greater than read & execute for standard user accounts or groups. The defaults below meet this requirement.Name - Authenticated UsersPermission - Read & executeApply To - This folder, subfolder and filesName - Server OperatorsPermission - Read & executeApply To - This folder, subfolder and filesName - AdministratorsPermission - SpecialApply To - This folder only(Permission - Special - Permissions: all selected except Full control, Delete subfolders and files)Name - CREATOR OWNERPermission - Special (Full control in Detail view)Apply To - Subfolders and files onlyName - AdministratorsPermission - Special (Full control in Detail view)Apply To - Subfolders and files onlyName - SYSTEMPermission - Full controlApply To - This folder, subfolders and files"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.2"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000281"
    
    def get_dod8500_2(self):
        return "ECAN-1, ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3,AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"