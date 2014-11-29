
#!/usr/bin/python
################################################################################
# V40177
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
        return r"V-40177"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Permissions for program file directories must conform to minimum requirements."

    def get_vulnerability_discussion(self):
        return r"Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.The default permissions are adequate when the Security Option ''Network access: Let everyone permissions apply to anonymous users'' is set to ''Disabled''. Maintain the default permissions for the program file directories and Set the Security Option: ''Network access: Let everyone permissions apply to anonymous users'' to ''Disabled'' .Default Permissions:\Program Files and \Program Files (x86)Type - ''Allow'' for allInherited from - ''None'' for allPrincipal - Access - Applies toTrustedInstaller - Full control - This folder and subfoldersSYSTEM - Modify - This folder onlySYSTEM - Full control - Subfolders and files onlyAdministrators - Modify - This folder onlyAdministrators - Full control - Subfolders and files onlyUsers - Read & execute - This folder, subfolders and filesCREATOR OWNER - Full control - Subfolders and files onlyALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012DC"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000412"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"