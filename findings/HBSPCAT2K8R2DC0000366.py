
#!/usr/bin/python
################################################################################
# V6836
#
# Justin Dierking
# phnomcobra@gmail.com
# justin.dierking@hardbitsolutions.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated SECEDIT finding
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
        return r"V-6836"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"For systems utilizing a logon ID as the individual identifier, passwords will, at a minimum, be 14 characters."

    def get_vulnerability_discussion(self):
        return r"Information systems not protected with strong password schemes including passwords of minimum length provide the opportunity for anyone to crack the password, thus, gaining access to the system and causing the device, information, or the local network to be compromised or a denial of service. Set the policy value for Computer Configuration \ Windows Settings \ Account Policies \ Password Policy \ ?Minimum password length,? to 14 characters."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Secedit Value
        value = cli.get_secedit_value('MinimumPasswordLength')

        # Output Lines
        self.__output = ["MinimumPasswordLength=" + value]
	
	# Recommended Value
	rec_value = ("14")

        if self.__verbose:
            print self.__output

	try:
            if int(value) >= int(rec_value):
                self.__is_compliant = True
        except ValueError:
            None

        return self.__is_compliant

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(D)"
    
    def get_pci(self):
        return "8.2.3"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000366"
    
    def get_dod8500_2(self):
        return "IAIA-1, IAIA-2"

    def get_800_53(self):
        return "IA-2, IA-4(2), IA-4(3), IA-5, IA-5(1), IA-5(3), IA-5(5), IA-5(6), IA-5(7)"
    
    def get_iso_27001(self):
        return "A.10.9.1, A.10.9.2, A.11.4.2, A.11.5.1, A.11.5.2 ,A.11.2.1, A.11.2.3, A.11.3.1, A.11.5.3"