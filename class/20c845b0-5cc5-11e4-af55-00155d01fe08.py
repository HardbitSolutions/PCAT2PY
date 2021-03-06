#!/usr/bin/python
################################################################################
# 20c845b0-5cc5-11e4-af55-00155d01fe08
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
        self.uuid = "20c845b0-5cc5-11e4-af55-00155d01fe08"
        
    def check(self, cli):
        # Initialize Compliance
        self.is_compliant = True
        
        # Execute command and parse capture standard output
        stdout = cli.system("grep ""^log_file"" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n")
      
        # Split output lines
        self.output = stdout.split('\n')

        # Process standard output
        for line in self.output:
            if len(line.strip()) > 0:
                sub_string = line.split(":")
                if int(sub_string[0]) > 755:
                    self.is_compliant = False
        
        return self.is_compliant

    def fix(self, cli):
        # Execute command and parse capture standard output
        stdout = cli.system("grep ""^log_file"" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n")
      
        # Split output lines
        self.__output = stdout.split('\n')

        # Process standard output
        for line in self.__output:
            if len(line.strip()) > 0:
                sub_string = line.split(":")
                if int(sub_string[0]) > 755:
                    cli.system("chmod go-w " + sub_string[1])
