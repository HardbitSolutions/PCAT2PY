
#!/usr/bin/python
################################################################################
# V8320
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
        return r"V-8320"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Directory server directories and files must be configured with required permissions."

    def get_vulnerability_discussion(self):
        return r"Improper access permissions for directory server program (executable) and configuration files could allow unauthorized and malicious users to read, modify, or delete those files and change the way a directory server operates. This could lead to a compromise of the confidentiality, availability, and integrity of directory data.Some administration tool packages (such as the Windows Support Tools) include programs designed to perform updates on directory configuration and database data. Even though the directory data should be protected through file and object access permissions, allowing unauthorized access to administrative programs provides a potential attacker with tools that are already installed in the environment. Set the directory service as follows:Windows Support Tools Permissions:  ...\Support Tools	 :Administrators, SYSTEM		:Full Control (F)		: [IAO-approved users \ user groups]  :Read, Read & Execute, List Folder Contents"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000208"
    
    def get_dod8500_2(self):
        return "DCSL-1"

    def get_800_53(self):
        return "CM-5(6)"
    
    def get_iso_27001(self):
        return "A.10.1.2, A.12.4.1, A.12.4.3, A.12.5.3"