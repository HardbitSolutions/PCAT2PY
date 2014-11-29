
#!/usr/bin/python
################################################################################
# V4407
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD EQ finding
#
# 09/21/2014 Original Construction
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
        return r"V-4407"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"LDAP server must sign all traffic sent to the client."

    def get_vulnerability_discussion(self):
        return r"By default, LDAP traffic is unsigned, which makes this traffic vulnerable to man . in . the . middle attacks. In this type of attack, an intruder captures packets between the server and the client and modifies them before forwarding them to the client. In the case of an LDAP server, this means that an attacker could cause a client to make decisions based on false records from the LDAP directory. This setting requires that the domain controller signs data sent to the client, which allows the client to verify that the data was not modified in transit. This is important because the client makes security decisions based on LDAP query results. For instance, member servers rely on LDAP queries to find out group membership or to determine which group policy objects should apply. If this policy is configured as ''none'', the server will not require data signatures but will provide them if requested by the client. The ''Require signature'' term means the domain contfoller will only bind with clients that negotiate LDAP data. Configure Domain Controller to require LDAP access signing."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters', 'LDAPServerIntegrity')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters', ('LDAPServerIntegrity=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\NTDS'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -name 'LDAPServerIntegrity' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000184"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"