#!/usr/bin/python
################################################################################
# 20d3b8e6-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "20d3b8e6-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False

        # Get Auditpol Value
        enabled = cli.get_auditpol(r'System Integrity', 'Failure')

        # Output Lines
        self.output = [r'System Integrity', ('Failure=' + str(enabled))]

        if enabled:
            self.is_compliant = True

        return self.is_compliant

    def fix(self, cli):
        cli.set_auditpol(r'System Integrity', 'Failure', True)
