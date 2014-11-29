
#!/usr/bin/python
################################################################################
# V6311
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
        return r"V-6311"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Logon options must be configured and enforced (Restricted Sites zone)."

    def get_vulnerability_discussion(self):
        return r"Users could submit credentials to servers operated by malicious individuals who could then attempt to connect to legitimate servers with those captured credentials. Care must be taken with user credentials, automatic logon performance, and how default Windows credentials are passed to websites. This policy setting allows management of settings for logon options. If you enable this policy setting, you can choose from varying logon options. ?Anonymous logon? disables HTTP authentication and uses the guest account only for the Common Internet File System (CIFS) protocol. ?Prompt for user name and password? queries users for user IDs and passwords. After a user is queried, these values can be used silently for the remainder of the session. ?Automatic logon only in Intranet zone? queries users for user IDs and passwords in other zones. After a user is queried, these values can be used silently for the remainder of the session. ?Automatic logon with current user name and password? attempts logon using Windows NT Challenge Response. If Windows NT Challenge Response is supported by the server, the logon uses the user''s network user name and password for login. If Windows NT Challenge Response is not supported by the server, the user is queried to provide the user name and password. If you disable this policy setting, logon is set to ?Automatic logon only in Intranet zone?. If you do not configure this policy setting, logon is set to ?Automatic logon only in Intranet zone?. The most secure option is to configure this setting to ?Enabled?; ?Anonymous logon?. This will prevent users from submitting credentials to servers in this security zone. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> ''Logon options'' to ''Enabled'', and select ''Anonymous logon'' from the drop-down box."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4', '1A00')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4', ('1A00=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 196608:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4' -name '1A00' -value 196608 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE10"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIETen000037"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"