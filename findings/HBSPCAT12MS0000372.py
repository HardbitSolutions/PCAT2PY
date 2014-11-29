
#!/usr/bin/python
################################################################################
# V36772
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
        return r"V-36772"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The machine account lockout threshold must be set to 10 on systems with BitLocker enabled."

    def get_vulnerability_discussion(self):
        return r"The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts should be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon. If BitLocker is enabled for the OS volumes, Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''Interactive logon: Machine account lockout threshold'' to ''10'' invalid logon attempts."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System', 'MaxDevicePasswordFailedAttempts')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System', ('MaxDevicePasswordFailedAttempts=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 10:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -name 'MaxDevicePasswordFailedAttempts' -value 10 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return "8.1.7"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000372"
    
    def get_dod8500_2(self):
        return "ECLO-1, ECLO-2"

    def get_800_53(self):
        return "AC-7, AC-7(1)"
    
    def get_iso_27001(self):
        return "A.11.5.1"