
#!/usr/bin/python
################################################################################
# V1114
#
# Justin Dierking
# justindierking@hardbitsolutions/com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated USER RIGHTS finding
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
        return r"V-1114"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The built-in guest account will be renamed."

    def get_vulnerability_discussion(self):
        return r"A system faces an increased vulnerability threat if the built-in guest account is not renamed or disabled.  The built-in guest account is a known user account on all Windows systems, and as initially installed, does not require a password.  This can allow access to system resources by unauthorized users.  This account is a member of the group Everyone and has all the rights and permissions associated with that group and could provide access to system resources to unauthorized users. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Accounts: Rename guest account? to a value other than ?Guest?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True

        # Get Accounts
        usernames = cli.get_secedit_account('NewGuestName')

        # Output Lines
        self.__output = [("NewGuestName=")] + usernames
	
	# Banned Usernames
	banned_usernames = ("Guest")

        if self.__verbose:
            print self.__output

	for user in usernames:
	    if user.lower().strip('"') in banned_usernames.lower():
	        self.__is_compliant = False

        return self.__is_compliant

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.308(a)(3)(ii)(B),164.308(a)(4)(i),164.308(a)(4)(ii)(B),164.308(a)(4)(ii)(C),164.308(a)(3)(ii)(C)"
    
    def get_pci(self):
        return "7.1.2,7.1.4,8.1.3"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000025"
    
    def get_dod8500_2(self):
        return "IAAC-1"

    def get_800_53(self):
        return "AC-2, PS-4, PS-5"
    
    def get_iso_27001(self):
        return "A.8.3.3, A.11.2.1, A.11.2.2, A.11.2.4, A.11.5.2, A.11.5.5, A.11.5.6, A.8.3.1, A.8.3.2, A.8.3.3"