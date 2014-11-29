
#!/usr/bin/python
################################################################################
# V36451
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MANUAL finding
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
        return r"V-36451"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Policy must require that administrative accounts not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email."

    def get_vulnerability_discussion(self):
        return r"Using applications that access the Internet or have potential Internet sources using administrative privileges exposes a system to compromise.  If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised.  Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative account.Since administrative accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy requires administrative accounts to not access the Internet or use applications, such as email.The policy should define specific exceptions for local service administration.  These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices. Establish a site policy to prohibit the use of applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, by administrative accounts.  Ensure the policy is enforced."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000317"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"