
#!/usr/bin/python
################################################################################
# V1095
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
        return r"V-1095"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Anonymous access to the event logs is not restricted."

    def get_vulnerability_discussion(self):
        return r"By default, the Windows event logs may be viewed over the network by an anonymous user.  This method of access over the network is communicating through the Server service which has SYSTEM access to the actual log files. Set the system to prevent guest access to the Event logs."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('SeAuditPrivilege')

        # Output Lines
        self.__output = ["SeAuditPrivilege=" + value]
	
	# Recommended Value
	rec_value = ("1")

        if self.__verbose:
            print self.__output

	if value.lower() == rec_value.lower():
	    self.__is_compliant = True

        return self.__is_compliant

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "10.5"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000018"
    
    def get_dod8500_2(self):
        return "ECTP-1"

    def get_800_53(self):
        return "AU-9"
    
    def get_iso_27001(self):
        return "A.10.10.3, A.13.2.3, A.15.1.3, A.15.3.2"