
#!/usr/bin/python
################################################################################
# V1090
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SZ EQ finding
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1090"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Caching of logon credentials is not limited."

    def get_vulnerability_discussion(self):
        return r"The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons such as the user''s machine is disconnected from the network or domain controllers are not available. Even though the credential cache is well-protected, storing encrypted copies of users passwords on systems do not always have the same physical protection required for domain controllers. If a system is attacked, the unauthorized individual may isolate the password to a domain user account using a password-cracking program, and gain access to the domain. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ?Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)? to ?2? logons or less."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'CachedLogonsCount')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', ('CachedLogonsCount=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "2":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'CachedLogonsCount' -value 2")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008MS"

    def get_hippa(self):
        return "164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8MS000014"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"