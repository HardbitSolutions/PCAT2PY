
#!/usr/bin/python
################################################################################
# V1099
#
# Justin Dierking
# justin.l.dierking.mil@mail.mil
# justin.l.dierking.civ@mail.mil
# phnomcobra@gmail.com
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
        return r"V-1099"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Lockout duration does not meet minimum requirements."

    def get_vulnerability_discussion(self):
        return r"This parameter specifies the amount of time that must pass before a locked-out account is automatically unlocked by the system. Set the system so that the bad logon lockout duration conforms to requirements."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('LockoutDuration')

        # Output Lines
        self.__output = ["LockoutDuration=" + value]
	
	# Recommended Value
	rec_value = ("0")

        if self.__verbose:
            print self.__output

	if value.lower() == rec_value.lower():
	    self.__is_compliant = True

        return self.__is_compliant

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return "8.1.7"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000022"
    
    def get_dod8500_2(self):
        return "ECLO-1, ECLO-2"

    def get_800_53(self):
        return "AC-7, AC-7(1)"
    
    def get_iso_27001(self):
        return "A.11.5.1"