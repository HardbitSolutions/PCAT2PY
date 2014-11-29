
#!/usr/bin/python
################################################################################
# V1097
#
# Justin Dierking
# phnomcobra@gmail.com
# justin.dierking@hardbitsolutions.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SECEDIT finding
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
        return r"V-1097"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Number of allowed bad-logon attempts does not meet minimum requirements."

    def get_vulnerability_discussion(self):
        return r"The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts should be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon. Set the system to lock out an account after three invalid logon attempts."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('LockoutBadCount')

        # Output Lines
        self.__output = ["LockoutBadCount=" + value]
	
	# Recommended Value
	rec_value = ("1 to 3")

        if self.__verbose:
            print self.__output

	try:
            if int(value) >= int(rec_value.split("to")[0]) and int(value) <= int(rec_value.split("to")[1]):
                self.__is_compliant = True
        except ValueError:
            None

        return self.__is_compliant

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return "8.1.6"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000017"
    
    def get_dod8500_2(self):
        return "ECLO-1, ECLO-2"

    def get_800_53(self):
        return "AC-7, AC-7(1)"
    
    def get_iso_27001(self):
        return "A.11.5.1"