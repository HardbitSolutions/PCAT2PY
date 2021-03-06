#!/usr/bin/python
################################################################################
# 20f2cbdc-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "20f2cbdc-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('LSAAnonymousNameLookup')

        # Output Lines
        self.output = ["LSAAnonymousNameLookup=" + value]
	
	# Recommended Value
	rec_value = ("0")

	if value.lower() == rec_value.lower():
	    self.is_compliant = True

        return self.is_compliant
