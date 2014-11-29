
#!/usr/bin/python
################################################################################
# V1145
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
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1145"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Automatic logons must be disabled."

    def get_vulnerability_discussion(self):
        return r"Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer.  Automatic logon with administrator privileges would give full access to an unauthorized individual. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)'' to ''Disabled''.Ensure no passwords are stored in the ''DefaultPassword'' registry value noted below:Registry Hive: HKEY_LOCAL_MACHINERegistry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Value Name: DefaultPassword(See ''Updating the Windows Security Options File'' in the STIG Overview document if MSS settings are not visible in the system''s policy tools.)"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'AutoAdminLogon')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', ('AutoAdminLogon=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "0":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'AutoAdminLogon' -value 0")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000033"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"