
#!/usr/bin/python
################################################################################
# V33673
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
        return r"V-33673"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Active Directory Group Policy objects must have proper access control permissions."

    def get_vulnerability_discussion(self):
        return r"When directory service database objects do not have appropriate access control permissions, it may be possible for malicious users to create, read, update, or delete the objects and degrade or destroy the integrity of the data.  When the directory service is used for identification, authentication, or authorization functions, a compromise of the database objects could lead to a compromise of all systems relying on the directory service.For Active Directory (AD), the Group Policy objects require special attention.  In a distributed administration model (i.e., help desk), Group Policy objects are more likely to have access permissions changed from the secure defaults.  If inappropriate access permissions are defined for Group Policy Objects, this could allow an intruder to change the security policy applied to all domain client computers (workstations and servers). Verify the access on Group Policy objects do not allow greater than Read and Apply group policy for standard user accounts or groups.  The defaults below meet this requirement.CREATOR OWNER - Special permissionsAuthenticated Users - Read, Apply group policy, Special permissionsThe Special permissions for Authenticated Users are for Read type Properties.SYSTEM - Read, Write, Create all child objects, Delete all child objects, Special permissionsDomain Admins - Read, Write, Create all child objects, Special permissionsEnterprise Admins - Read, Write, Create all child objects, Special permissionsENTERPRISE DOMAIN CONTROLLERS - Read, Special permissionsDocument any other access permissions that allow the objects to be updated with the IAO."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.2"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000303"
    
    def get_dod8500_2(self):
        return "ECAN-1, ECCD-1, ECCD-2, ECLP-1"

    def get_800_53(self):
        return "AC-3(3), AC-3(4),AC-3,AC-5, AC-6, AC-6(2)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3, A.10.1.3, A.11.4.1, A.11.4.4"