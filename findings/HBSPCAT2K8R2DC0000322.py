
#!/usr/bin/python
################################################################################
# V3458
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD RANGE finding
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
        return r"V-3458"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Remote Desktop Services will be configured to disconnect an idle session after the specified time period."

    def get_vulnerability_discussion(self):
        return r"This setting controls how long a session may be idle before it is automatically disconnected from the server.  Users should disconnect if they plan on being away from their terminals for extended periods of time.  Idle sessions should be disconnected after 15 minutes. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Remote Desktop Services \ Remote Desktop Session Host \ Session Time Limits ?Set time limit for active but idle Remote Desktop Services sessions? to ?Enabled?, and the ?Idle session limit? to 15 minutes or less, excluding 0 which equates to ?Never?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', 'MaxIdleTime')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services', ('MaxIdleTime=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword >= 1  or dword <=  900000:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -name 'MaxIdleTime' -value 1 to 900000 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "8.1.8"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000322"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"