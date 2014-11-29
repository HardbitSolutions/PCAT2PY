
#!/usr/bin/python
################################################################################
# V41344
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
        return r"V-41344"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"WEBSERVICE functions must be disabled."

    def get_vulnerability_discussion(self):
        return r"The WEBSERVICE function option, when used in an Excel spreadsheet, returns data from a web service on the Internet or Intranet. If allowed to be used, security is significantly reduced by allowing information disclosure to third party web services and could potentially introduce malicious content to the local network. The WEBSERVICE function must be disabled in Excel and configured to notify user if a WEBSERVICE function is present in an Excel spreadsheet. Set policy value for User Configuration \ Administrative Templates \ Microsoft Excel 2013 \ Excel Options \ Security \ '' WEBSERVICE Function Notification Settings'' is set to ''Enabled: Disable all with notifications''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\excel\security', 'webservicefunctionwarnings')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\excel\security', ('webservicefunctionwarnings=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\excel'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\excel\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\excel\security' -name 'webservicefunctionwarnings' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Excel"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Excel0046"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"