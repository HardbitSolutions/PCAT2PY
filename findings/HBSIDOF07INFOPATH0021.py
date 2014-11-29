
#!/usr/bin/python
################################################################################
# V17667
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
        return r"V-17667"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable sending the form template with the eMail form in InfoPath."

    def get_vulnerability_discussion(self):
        return r"By default, InfoPath 2007 allows users to attach form templates when sending e-mail forms. If users are able to open form templates included with e-mail forms, rather than using a cached version that is previously published, an attacker could send a malicious form template with the e-mail form in an attempt to gain access to sensitive information.Note   The form template is only opened directly if the form opens with a restricted security level. Otherwise the attachment is actually a link to the published location. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office InfoPath 2007 \ InfoPath e-mail forms ?Disable sending form template with e-mail forms? will be set to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Deployment', 'MailXSNwithXML')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Deployment', ('MailXSNwithXML=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Deployment'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Deployment' -name 'MailXSNwithXML' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07InfoPath0021"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"