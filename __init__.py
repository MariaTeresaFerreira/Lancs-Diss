import os
import firewall_checks as fwc
import sec_configs_checks as scc
import extras as ext



if __name__ == "__main__":
    all_dicts = fwc.get_all_firewall_dicts()
    #ext.print_dicts(all_dicts)
    print("FIREWALL CHECKS: ")
    ext.print_tests(1, fwc.firewall_check_1(all_dicts))
    ext.print_tests(3, fwc.firewall_check_3(all_dicts))
    print("SECURE CONFIGURATION CHECKS: ")
    ext.print_tests(1, scc.configs_check_1())
    ext.print_tests(3, scc.configs_check_3())
    ext.print_tests(4, scc.configs_check_4())
    ext.print_tests(5, scc.configs_check_5())


    
    

    
    