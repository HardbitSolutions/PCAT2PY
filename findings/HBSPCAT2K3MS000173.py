
#!/usr/bin/python
################################################################################
# V6825
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
        return r"V-6825"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"A Windows system has an incorrect default DCOM authorization level."

    def get_vulnerability_discussion(self):
        return r"The DCOM default authentication level has been detected to be below the required setting. If the authentication level is None, then any user can access any object on the system without authentication. Fortify DCOMs default permissions.  This should be thoroughly tested to verify DCOM objects continue to function under tightened security.Open a command prompt.Execute ?Dcomcnfg.exe?.In the ?Component Services? window, navigate to Component Services \ Computer \ My Computer Right-click ?My Computer? and select ?Properties?.Select the ?Default Properties? tab. Select a ?Default Authentication Level? other than ?None? or ?Call?.  For sensitive systems, an authentication level of ?Packet Privacy? is recommended. Click OK."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000173"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"