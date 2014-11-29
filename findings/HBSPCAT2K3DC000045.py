
#!/usr/bin/python
################################################################################
# V1130
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
        return r"V-1130"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"ACLs for system files and directories do not conform to minimum requirements."

    def get_vulnerability_discussion(self):
        return r"Failure to properly configure ACL file and directory permissions, allows the possibility of unauthorized and anonymous modification to the operating system and installed applications. Maintain the default file ACLs, Set the Security Option: ?Network access: Let everyone permissions apply to anonymous users? to ?Disabled? and restrict the Power Users group to include no members.Configure permissions on the following so that only Administrators and System have Full (no other permissions assigned to other accounts or groups).\regedit.exe\System32\arp.exe\System32\at.exe\System32\attrib.exe\System32\cacls.exe\System32\debug.exe\System32\edlin.exe\System32\eventcreate.exe\System32\eventtriggers.exe\System32\ftp.exe\System32\nbtstat.exe\System32\net.exe\System32\net1.exe\System32\netsh.exe\System32\netstat.exe\System32\nslookup.exe\System32\ntbackup.exe\System32\rcp.exe\System32\reg.exe\System32\regedt32.exe\System32\regini.exe\System32\regsvr32.exe\System32\rexec.exe\System32\route.exe\System32\rsh.exe\System32\sc.exe\System32\secedit.exe\System32\subst.exe\System32\Systeminfo.exe\System32\telnet.exe\System32\tftp.exe\System32\tlntsvr.exe"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "2003DC"

    def get_hippa(self):
        return "164.312(a)(1)"
    
    def get_pci(self):
        return "7.1"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3DC000045"
    
    def get_dod8500_2(self):
        return "ECCD-1, ECCD-2"

    def get_800_53(self):
        return "AC-3, AC-3(3), AC-3(4)"
    
    def get_iso_27001(self):
        return "A.7.2.2, A.10.6.1, A.10.7.3, A.10.7.4, A.10.8.1 A.10.9.1, A.10.9.2, A.10.9.3, A.11.2.2, A.11.5.4, A.11.6.1, A.12.4.3, A.15.1.3"