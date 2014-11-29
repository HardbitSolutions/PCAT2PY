
#!/usr/bin/python
################################################################################
# V3337
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
        return "CAT I"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-3337"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Anonymous SID/Name translation must not be allowed."

    def get_vulnerability_discussion(self):
        return r"Allowing anonymous SID/Name translation can provide sensitive information for accessing a system.  Only authorized users must be able to perform such translations. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''Network access: Allow anonymous SID/Name translation'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('LSAAnonymousNameLookup')

        # Output Lines
        self.__output = ["LSAAnonymousNameLookup=" + value]
	
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
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000297"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"