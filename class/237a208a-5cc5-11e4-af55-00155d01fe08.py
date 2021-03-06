#!/usr/bin/python
################################################################################
# 237a208a-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "237a208a-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep PASS_MIN_DAYS /etc/login.defs")
        
        # Split output lines
        self.output = stdout.split('\n')

        # Process standard output
        for line in self.output:
            if line.startswith("PASS_MIN_DAYS"):
                sub_string = (line[13:]).strip()
                if int(sub_string) >= 1:
                    self.is_compliant = True
                
        return self.is_compliant

    def fix(self, cli):
        cli.system("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS  1/g' /etc/login.defs")
