
#!/usr/bin/python
################################################################################
# V4108
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD LE finding
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
        return r"V-4108"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system must generate an audit event when the audit log reaches a percentage of full threshold."

    def get_vulnerability_discussion(self):
        return r"When the audit log reaches a given percent full, an audit event is written to the security log.  It is recorded as a successful audit event under the category of System.  This option may be especially useful if the audit logs are set to be cleared manually. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning'' to ''90'' or less.(See ''Updating the Windows Security Options File'' in the STIG Overview document if MSS settings are not visible in the system''s policy tools.)"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Services\Eventlog\Security', 'WarningLevel')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Services\Eventlog\Security', ('WarningLevel=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword <= 90:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Eventlog'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Services\Eventlog\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Eventlog\Security' -name 'WarningLevel' -value 90 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312(b),164.312(c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000394"
    
    def get_dod8500_2(self):
        return "ECRR-1"

    def get_800_53(self):
        return "AU-11"
    
    def get_iso_27001(self):
        return "A.10.10.1, A.13.2.3, A.15.1.3"