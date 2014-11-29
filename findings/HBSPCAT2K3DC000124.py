
#!/usr/bin/python
################################################################################
# V3338
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MULTISZ ARRAY finding
#
# 09/23/2014 Original Construction
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
        return r"V-3338"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Unauthorized named pipes are accessible with anonymous credentials."

    def get_vulnerability_discussion(self):
        return r"This is a high priority finding because the potential for gaining unauthorized system access.  Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  This setting controls which of these pipes anonymous users may access. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Network access: Named pipes that can be accessed anonymously? as defined."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True

        # Get Registry MultiSZ 
        multi_sz = cli.get_reg_multi_sz(r'HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters', 'NullSessionPipes')

        # Output Lines
        self.__output = [r'HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters', ('NullSessionPipes=')] + multi_sz
	
	# Recommended MultiSZ
	rec_multi_sz = ("COMNAP,COMNODE,SQL\QUERY,SPOOLSS,LLSRPC,BROWSER,NETLOGON,LSARPC,SAMR")

        if self.__verbose:
            print self.__output

	for sz in multi_sz:
	    if sz.lower() not in rec_multi_sz.lower():
	        self.__is_compliant = False

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\SYSTEM\CurrentControlSet\services'")
        cli.powershell(r"New-Item -path 'HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer'")
        cli.powershell(r"New-Item -path 'HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters' -name 'NullSessionPipes' -Type MultiString -value COMNAP,COMNODE,SQL\QUERY,SPOOLSS,LLSRPC,BROWSER,NETLOGON,LSARPC,SAMR")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000124"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"