
#!/usr/bin/python
################################################################################
# V36713
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
        return r"V-36713"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Windows Remote Management (WinRM) client must not allow unencrypted traffic."

    def get_vulnerability_discussion(self):
        return r"Unencrypted remote access to a system can allow sensitive information to be compromised.  Windows remote management connections must be encrypted to prevent this. Set the policy value for Computer Configuration \ Administrative Templates \ Windows Components \ Windows Remote Management (WinRM) \ WinRM Client \ ''Allow unencrypted traffic'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client', 'AllowUnencryptedTraffic')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client', ('AllowUnencryptedTraffic=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\WinRM'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client' -name 'AllowUnencryptedTraffic' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312(a)(2)(iv),164.312(e)(2)(ii)"
    
    def get_pci(self):
        return "8.3,8.5,4.1,3.6,2.3"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000360"
    
    def get_dod8500_2(self):
        return "ECCT-1"

    def get_800_53(self):
        return "AC-17(2),AC-18(1),SC-9,SC-9(1),SC-13,SC-13(1)"
    
    def get_iso_27001(self):
        return "A.10.6.1, A.10.8.1, A.10.8.5, A.11.4.1, A.11.4.2, A.11.4.6,  A.11.7.1, A.11.7.2, A.10.9.1, A.10.9.2, A.15.1.6"