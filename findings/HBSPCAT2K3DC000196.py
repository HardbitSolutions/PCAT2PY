
#!/usr/bin/python
################################################################################
# V6826
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
        return r"V-6826"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"A Windows system has a writable DCOM configuration."

    def get_vulnerability_discussion(self):
        return r"A registry key for a valid DCOM object has access permissions that allow non-administrator users to change the security settings. If DCOM security settings are inadvertently set to a low level of security, it may be possible for an attacker to execute code, possibly under the user context of the console user.In addition, an attacker could change the security on the object to allow for a future attack, such as setting the object to run as Interactive User. The Interactive User runs the application using the security context of the user currently logged on to the computer. If this option is selected and the user is not logged on, then the application will not start. Fortify DCOMs AppId permissions.  Any changes should be thoroughly tested so objects continue to function under tightened security.- Open the Registry Editor.- Navigate to HKEY_LOCAL_MACHINE\Software\Classes\Appid.- Select the application that generated this vulnerability.- Set the permissions for standard (non-privileged) user accounts or groups to Read only."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000196"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"