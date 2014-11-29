
#!/usr/bin/python
################################################################################
# V12780
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
        return r"V-12780"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Synchronize directory service data user right must be configured to include no accounts or groups (blank)."

    def get_vulnerability_discussion(self):
        return r"A Windows account with the ''Synchronize directory service data'' right has the ability to read all information in the AD database.  This bypasses the object access permissions that would otherwise restrict access to the data.  The scope of access granted by this right is too broad for secure usage.  Specific object permissions or other group membership assignments could be used to provide access on an appropriate scale. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ User Rights Assignment \ ''Synchronize directory service data'' to be defined but containing no entries (blank)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('SeSyncAgentPrivilege')

        # Output Lines
        self.__output = ["SeSyncAgentPrivilege=" + value]
	
	# Recommended Value
	rec_value = ("")

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
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.2"
    
    def get_hbs_id(self):
        return "HBSPCAT12DC0000055"
    
    def get_dod8500_2(self):
        return "ECAN-1, ECCD-1, ECCD-2, ECLP-1"

    def get_800_53(self):
        return "AC-3(3), AC-3(4),AC-3,AC-5, AC-6, AC-6(2)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3, A.10.1.3, A.11.4.1, A.11.4.4"