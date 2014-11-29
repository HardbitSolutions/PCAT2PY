
#!/usr/bin/python
################################################################################
# V4443
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
        return r"V-4443"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Unauthorized remotely accessible registry paths and sub-paths will not be configured."

    def get_vulnerability_discussion(self):
        return r"The registry is a database for computer configuration information, much of which is sensitive. An attacker could use this to facilitate unauthorized activities. To reduce the risk of this happening, it is also lowered by the fact that the default ACLs assigned throughout the registry are fairly restrictive and they help to protect it from access by unauthorized users. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Network access: Remotely accessible registry paths and sub-paths? as defined."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = True

        # Get Registry MultiSZ 
        multi_sz = cli.get_reg_multi_sz(r'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths', 'Machine')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths', ('Machine=')] + multi_sz
	
	# Recommended MultiSZ
	rec_multi_sz = ("Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Perflib,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,System\CurrentControlSet\Services\Eventlog,System\CurrentControlSet\Services\Sysmonlog")

        if self.__verbose:
            print self.__output

	for sz in multi_sz:
	    if sz.lower() not in rec_multi_sz.lower():
	        self.__is_compliant = False

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' -name 'Machine' -Type MultiString -value Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Perflib,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,System\CurrentControlSet\Services\Eventlog,System\CurrentControlSet\Services\Sysmonlog")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000356"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"