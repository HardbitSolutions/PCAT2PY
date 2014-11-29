
#!/usr/bin/python
################################################################################
# V15566
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
        return r"V-15566"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Internet Explorer Processes for MIME handling is not enabled. (IExplore)"

    def get_vulnerability_discussion(self):
        return r"Internet Explorer uses Multipurpose Internet Mail Extensions (MIME) data to determine file handling procedures for files received through a Web server. The Consistent MIME Handling\Internet Explorer Processes policy setting determines whether Internet Explorer requires that all file-type information provided by Web servers be consistent. For example, if the MIME type of a file is text/plain but the MIME data indicates that the file is really an executable file, Internet Explorer changes its extension to reflect this executable status. This capability helps ensure that executable code cannot masquerade as other types of data that may be trusted.  If you enable this policy setting, Internet Explorer examines all received files and enforces consistent MIME data for them. If you disable or do not configure this policy setting, Internet Explorer does not require consistent MIME data for all received files and will use the MIME data provided by the file.  MIME file-type spoofing is a potential threat to your organization. Ensuring that these files are consistent and properly labeled helps prevent malicious file downloads from infecting your network. This guide recommends you configure this policy as Enabled for all environments specified in this guide. Manipulate the value: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING Criteria: Set the value iexplore.exe to REG_SZ = 1."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        sz = cli.get_reg_sz(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING', 'iexplore.exe')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING', ('iexplore.exe=' + sz)]

        if self.__verbose:
            print self.__output

        if sz == "1":
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING' -name 'iexplore.exe' -value 1")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE8"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE8000080"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"