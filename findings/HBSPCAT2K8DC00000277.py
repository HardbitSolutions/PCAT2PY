
#!/usr/bin/python
################################################################################
# V8322A
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
        return r"V-8322A"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Time synchronization must be enabled on the domain controller."

    def get_vulnerability_discussion(self):
        return r"When a directory service using multi-master replication (such as AD) executes on computers that do not have synchronized time, directory data may be corrupted or updated invalidly.The lack of synchronized time could lead to audit log data that is misleading, inconclusive, or unusable. In cases of intrusion, this may invalidate the audit data as a source of forensic evidence in an incident investigation.In AD, the lack of synchronized time could prevent clients from logging on or accessing server resources as a result of Kerberos requirements related to time variance. Ensure the Windows Time Service is configured as follows or install and enable another time synchronization tool.Registry Hive: HKEY_LOCAL_MACHINERegistry Path: \System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient\Value Name: EnabledType: REG_DWORDValue: 1Registry Path: \System\CurrentControlSet\Services\W32Time\ Parameters\Value Name: TypeType: REG_SZValue: NT5DS (preferred), NTP, or Allsync"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient', 'Enabled')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient', ('Enabled=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\W32Time'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient' -name 'Enabled' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.312(c)(1),164.312(c)(2),164.312(e)(2)(i)"
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000277"
    
    def get_dod8500_2(self):
        return "ECTM-1, ECTM-2"

    def get_800_53(self):
        return "SC-8, SC-8(2), SI-7,SC-16,SC-23"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3, A.10.10.2, A.12.2.2, A.12.2.3, A.12.4.1, A.10.6.1, A.10.8.1, A.10.8.4, A.10.9.1, A.10.9.2, A.7.2.2"