
#!/usr/bin/python
################################################################################
# V26486
#
# Justin Dierking
# justin.l.dierking.mil@mail.mil
# justin.l.dierking.civ@mail.mil
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
        return r"V-26486"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and local administrator accounts on domain systems, and from unauthenticated access on all systems."

    def get_vulnerability_discussion(self):
        return r"Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.The ''Deny log on through Remote Desktop Services'' user right defines the accounts that are prevented from logging on using Remote Desktop Services.In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.Local administrator accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.The Guests group must be assigned this right to prevent unauthenticated access. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ User Rights Assignment \ ''Deny log on through Remote Desktop Services'' to include the following:Domain Systems Only:Enterprise Admins GroupDomain Admins Group*All Local Administrator AccountsAll Systems:Guests Group*Note: Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True

        # Get Accounts
        usernames = cli.get_secedit_account('SeDenyNetworkLogonRight')

        # Output Lines
        self.__output = [("SeDenyNetworkLogonRight=")] + usernames
	
	# Recommended MultiSZ
	rec_usernames = ("BUILTIN\Guests,Enterprise Admins,Domain Admins,BUILTIN\Administrators")

        if self.__verbose:
            print self.__output

	for user in usernames:
	    if user.lower() not in rec_usernames.lower():
	        self.__is_compliant = False

        return self.__is_compliant

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000212"
    
    def get_dod8500_2(self):
        return "ECLP-1"

    def get_800_53(self):
        return "AC-5, AC-6, AC-6(2)"
    
    def get_iso_27001(self):
        return "A.10.1.3, A.11.2.2, A.11.4.1, A.11.4.4, A.11.5.4, A.11.6.1, A.12.4.3"