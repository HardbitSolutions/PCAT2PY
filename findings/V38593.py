#!/usr/bin/python
################################################################################
# V38593
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
#
# 06/07/2014 Original construction
# 07/02/2014 Set __output with stdout
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
        return "SV-50394r1_rule"
    
    def get_rule_version(self):
        return "RHEL-06-000073"
    
    def get_group_id(self):
        return "V-38593"
    
    def get_group_title(self):
        return "SRG-OS-000228"
    
    def get_rule_title(self):
        return "The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts."
    
    def get_vulnerability_discussion(self):
        return "An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers."
    
    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)
        
    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False
        
        # Execute command and parse capture standard output
        stdout = cli.system("cat /etc/issue")
        
        # Split stdout
        self.__output = stdout.split('\n')
        
        # Process standard output
        if "attorneys, psychotherapists, or clergy" in stdout:
            self.__is_compliant = True
        
        return self.__is_compliant
    
    def fix(self, cli):
        cli.system("/dev/null > /etc/issue")
        cli.system('echo "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:" >> /etc/issue')
        cli.system('echo "-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations." >> /etc/issue')
        cli.system('echo "-At any time, the USG may inspect and seize data stored on this IS." >> /etc/issue')
        cli.system('echo "-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose." >> /etc/issue')
        cli.system('echo "-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy." >> /etc/issue')
        cli.system('echo "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." >> /etc/issue')
    
    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "RHEL6"