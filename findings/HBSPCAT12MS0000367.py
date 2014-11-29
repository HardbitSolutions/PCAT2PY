
#!/usr/bin/python
################################################################################
# V36724
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MANUAL finding
#
# 09/30/2014 Original Construction
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
        return r"V-36724"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Permissions for the System event log must prevent access by nonprivileged accounts."

    def get_vulnerability_discussion(self):
        return r"Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The System event log may be  susceptible to tampering if proper permissions are not applied. Verify the access on the System event log (System.evtx) are configured to prevent standard user accounts or groups from having greater than Read access.  The default permissions listed below satisfy this requirement:Eventlog - Full ControlSYSTEM - Full ControlAdministrators - Full ControlThe default location is the ''%SystemRoot%\SYSTEM32\WINEVT\LOGS'' directory.If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as ''NT Service\Eventlog''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "10.5"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000367"
    
    def get_dod8500_2(self):
        return "ECTP-1"

    def get_800_53(self):
        return "AU-9"
    
    def get_iso_27001(self):
        return "A.10.10.3, A.13.2.3, A.15.1.3, A.15.3.2"