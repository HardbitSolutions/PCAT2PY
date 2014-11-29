
#!/usr/bin/python
################################################################################
# V14831
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-14831"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The directory service must be configured to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity."

    def get_vulnerability_discussion(self):
        return r"The failure to terminate inactive network connections increases the risk of a successful attack on the directory server. The longer an established session is in progress, the more time an attacker has to hijack the session, implement a means to passively intercept data, or compromise any protections on client access. For example, if an attacker gains control of a client computer, an existing (already authenticated) session with the directory server could allow access to the directory. The lack of confidentiality protection in LDAP-based sessions increases exposure to this vulnerability. Set the directory service to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity.Open an elevated command prompt.Enter ''ntdsutil''.At the ''ntdsutil:'' prompt, enter ''LDAP policies''.At the ''ldap policy:'' prompt, enter ''connections''.At the ''server connections:'' prompt, enter ''connect to server [host-name]''.(Where [host-name] is the computer name of the domain controller.)At the ''server connections:'' prompt, enter ''q''.At the ''ldap policy:'' prompt, enter ''Set MaxConnIdleTime to 300''.Enter ''Commit Changes'' to save.Enter ''Show values'' to verify changes.Enter ''q'' at the ''ldap policy:'' and ''ntdsutil:'' prompts to exit."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312(c)(1),164.312(c)(2),164.312(e)(2)(i)"
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000108"
    
    def get_dod8500_2(self):
        return "ECTM-1, ECTM-2"

    def get_800_53(self):
        return "SC-8, SC-8(2), SI-7,SC-16,SC-23"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3, A.10.10.2, A.12.2.2, A.12.2.3, A.12.4.1, A.10.6.1, A.10.8.1, A.10.8.4, A.10.9.1, A.10.9.2, A.7.2.2"