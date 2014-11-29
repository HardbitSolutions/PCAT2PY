
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
        return r"The lockout duration must be configured to require an administrator to unlock an account."

    def get_vulnerability_discussion(self):
        return r"The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.  A value of 0 will require an administrator to unlock the account. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Account Policies \ Account Lockout Policy \ ''Account lockout duration'' to ''0'' minutes, ''Account is locked out until administrator unlocks it''."

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
        return "2012DC"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return "8.1.7"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000015"
    
    def get_dod8500_2(self):
        return "ECLO-1, ECLO-2"

    def get_800_53(self):
        return "AC-7, AC-7(1)"
    
    def get_iso_27001(self):
        return "A.11.5.1"