
#!/usr/bin/python
################################################################################
# V39331
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
        return r"V-39331"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Active Directory SYSVOL directory must have the proper access control permissions."

    def get_vulnerability_discussion(self):
        return r"Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete directory data.The SYSVOL directory contains public files (to the domain) such as policies and logon scripts.  Data in shared subdirectories are replicated to all domain controllers in a domain. Verify the access on SYSVOL directory do not allow greater than read & execute for standard user accounts or groups.  The defaults below meet this requirement.Type - Allow Principal - Authenticated UsersAccess - Read & executeInherited from - NoneApplies to - This folder, subfolder and filesType - Allow Principal - Server OperatorsAccess - Read & executeInherited from - NoneApplies to - This folder, subfolder and filesType - Allow Principal - AdministratorsAccess - SpecialInherited from - NoneApplies to - This folder only(Access - Special - Basic Permissions: all selected except Full control)Type - Allow Principal - CREATOR OWNERAccess - Full controlInherited from - NoneApplies to - Subfolders and files onlyType - Allow Principal - AdministratorsAccess - Full controlInherited from - NoneApplies to - Subfolders and files onlyType - Allow Principal - SYSTEMAccess - Full controlInherited from - NoneApplies to - This folder, subfolders and files"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000404"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"