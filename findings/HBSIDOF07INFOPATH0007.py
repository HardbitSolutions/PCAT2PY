
#!/usr/bin/python
################################################################################
# V17576
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
        return r"V-17576"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Block redirection behavior for upgraded web sites by SharePoint - Infopath."

    def get_vulnerability_discussion(self):
        return r"During a Windows SharePoint Services gradual upgrade, sites that have been upgraded remain available at their original URLs (for example, http://<company_name>/sites/SiteA), while sites that are still in the process of being upgraded are located at a temporary domain URL (for example, http://<company_name_old>/sites/SiteB).By default, InfoPath 2007 automatically redirects user requests for sites that have not been upgraded to the temporary URL if it is located on the local intranet, but blocks them if the temporary URL is located elsewhere. InfoPath will prompt users before redirecting forms or form templates to another intranet site.If this restriction is relaxed, all requests to sites that have not been upgraded will be redirected to their targets, regardless of location. This functionality could cause requests made to a secure site to be redirected to an unsecured one (for example, requests to an intranet site could be redirected to an unencrypted Internet site), causing sensitive information to be at risk. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office InfoPath 2007 \ Security \ ?Control behavior for Windows SharePoint Services gradual upgrade? will be set to ?Enabled (Block all redirections)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Security', 'GradualUpgradeRedirection')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Security', ('GradualUpgradeRedirection=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 2:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Security' -name 'GradualUpgradeRedirection' -value 2 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07InfoPath0007"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"