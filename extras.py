class colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    DEFAULT = '\033[0m'

errors = {
    "scc_01": "Guest or Administrator user is enabled, confirm if this is necessary",
    "scc_03": "Autoplay is enabled",
    "ssc_04": "Active users are not as expected",
    "ssc_05": "Administrator users are not as expected"
}

#print(f"{colours.YELLOW}===== STARTING ", test_file, f" CHECKS =====\n{colours.DEFAULT}")

def print_tests(number, value):
    if value == True:
        print(f"Check" , number, f"-> {colours.GREEN}Pass{colours.DEFAULT}")
    elif value == False:
        print(f"Check" , number, f"-> {colours.RED}Fail{colours.DEFAULT}")
    else:
        print(f"Check" , number, f"-> {colours.YELLOW}Possible Vulnerability {colours.DEFAULT}(" + value +  "):", errors[value] )


def print_dicts(dicts):
    for dict in dicts:
        #print("===========")
        for elem in dict:
            print(elem, ":", dict[elem])