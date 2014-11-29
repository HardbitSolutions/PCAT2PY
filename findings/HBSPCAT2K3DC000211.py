
#!/usr/bin/python
################################################################################
# V8324
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD OR finding
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
        return r"V-8324"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The time synchronization tool must be configured to enable logging of time source switching."

    def get_vulnerability_discussion(self):
        return r"When a time synchronization tool executes, it may switch between time sources according to network or server contention.  If switches between time sources are not logged, it may be difficult or impossible to detect malicious activity or availability problems. Set the time synchronization tool to log time source switching.  If the Windows Time Service is used, Set the following registry value.Registry Hive: HKEY_LOCAL_MACHINERegistry Path: \System\CurrentControlSet\Services\W32Time\Config\Value Name: EventLogFlagsType: REG_DWORDValue: 2 or 3"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\W32Time\Config', 'EventLogFlags')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\W32Time\Config', ('EventLogFlags=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2  or dword ==  3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\W32Time'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\W32Time\Config'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\W32Time\Config' -name 'EventLogFlags' -value 2 or 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312(c)(1),164.312(c)(2),164.312(e)(2)(i)"
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000211"
    
    def get_dod8500_2(self):
        return "ECTM-1, ECTM-2"

    def get_800_53(self):
        return "SC-8, SC-8(2), SI-7,SC-16,SC-23"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3, A.10.10.2, A.12.2.2, A.12.2.3, A.12.4.1, A.10.6.1, A.10.8.1, A.10.8.4, A.10.9.1, A.10.9.2, A.7.2.2"