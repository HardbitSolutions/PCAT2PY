
#!/usr/bin/python
################################################################################
# V3342
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
        return r"V-3342"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The computer does not wait for the network at computer startup."

    def get_vulnerability_discussion(self):
        return r"The setting determines if Windows waits for complete network initialization before allowing the user to log on.  Part of this initialization is the application of Group Policy.  This may permit a User to log on before all GPOs (Group Policy Objects) are obtained and processed and so the user may operate under the incorrect security context for a time. Set the system to wait for complete network initialization before allowing a user to log on.  This is done by setting the policy value for Computer Configuration \ Administrative Templates \ System \ Logon ?Always Wait for the Network at Computer Startup and Logon? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon', 'SyncForegroundPolicy')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon', ('SyncForegroundPolicy=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'SyncForegroundPolicy' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000108"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"