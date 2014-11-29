#!/usr/bin/python
################################################################################
# 21153dde-5cc5-11e4-af55-00155d01fe08
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# 10/24/2014 Original Construction
################################################################################

class Finding:
    def __init__(self):
        self.output = []
        self.is_compliant = False
        self.uuid = "21153dde-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = True

        # Get Accounts
        usernames = cli.get_secedit_account('SeEnableDelegationPrivilege')

        # Output Lines
        self.output = [("SeEnableDelegationPrivilege=")] + usernames
	
	# Recommended MultiSZ
	rec_usernames = ("")

	for user in usernames:
	    if user.lower() not in rec_usernames.lower():
	        self.is_compliant = False

        return self.is_compliant