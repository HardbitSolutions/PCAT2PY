
#!/usr/bin/python
################################################################################
# V36440
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
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-36440"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts."

    def get_vulnerability_discussion(self):
        return r"Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if credentials are compromised.  Limiting inbound connections only from authorized remote management systems will help limit this exposure. Configure firewall exceptions to inbound connections on domain workstations to include only authorized remote management hosts.Configure only inbound connection exceptions for authorized remote management hosts.Computer Configuration \ Windows Settings \ Security Settings \ Windows Firewall with Advanced Security \ Windows Firewall with Advanced Security \ Inbound Rules (this link will be in the right pane) \ For any inbound rules that allow connections, Set the Scope for Remote IP address to those of authorized remote management hosts.  This may be defined as an IP address, subnet or range.  Apply the rule to all firewall profiles.If a third-party firewall is used, configure inbound exceptions to only include authorized remote management hosts."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.312(e)(1)"
    
    def get_pci(self):
        return "1.2.1"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000285"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"