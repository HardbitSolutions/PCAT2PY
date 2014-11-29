
#!/usr/bin/python
################################################################################
# V14270
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
        return r"V-14270"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Notify antivirus when file attachments are opened."

    def get_vulnerability_discussion(self):
        return r"This check verifies that antivirus programs are notified when a user opens a file attachment. Configure policy value for User Configuration \ Administrative Templates \ Windows Components \ Attachment Manager \ ?Notify antivirus programs when opening attachments? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments', 'ScanWithAntiVirus')

        # Output Lines
        self.__output = [r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments', ('ScanWithAntiVirus=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' -name 'ScanWithAntiVirus' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(B)"
    
    def get_pci(self):
        return "5.1, 5.2"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8DC00000102"
    
    def get_dod8500_2(self):
        return "ECVP-1"

    def get_800_53(self):
        return "SI-3"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3"