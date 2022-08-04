from asyncio.windows_events import NULL
import subprocess
import win32net
import re

def get_firewall_dict(name):
    options = [
        'State',
        'Firewall Policy',
        'LocalFirewallRules',
        'LocalConSecRules',
        'InboundUserNotification',
        'RemoteManagement',
        'UnicastResponseToMulticast',
        'LogAllowedConnections',
        'LogDroppedConnections',
        'FileName',
        'MaxFileSize']

    out = (subprocess.check_output('netsh advfirewall show ' + name, shell=True)).decode("utf-8")
    dict = {}
    dict["Name"] = name
    out_split = re.split('\n', out)
    for line in out_split:
        entry = line.split()
        if (len(entry) != 0) and (entry[0] in options):
            key = entry[0]
            entry.pop(0)
            dict[key] = ' '.join(entry)
    
    return dict

def get_all_firewall_dicts():
    '''Returns a list of 3 dictionaries that correspond to the three types of firewall (Domain, Private, and Public), the dictionaries have the settings of the firewall'''
    return [get_firewall_dict("Domain"), get_firewall_dict("Private"), get_firewall_dict("Public")]


def firewall_check_1(dicts):
    '''Returns True if all three firewall options are enabled, False if at least one of them is not'''
    for dic in dicts:
        if dic['State'] == 'OFF':
            return False
    return True

def firewall_check_2():
    (a, b) = win32net.NetValidatePasswordPolicy(NULL, NULL, )
    print("a: ", a)
    print("b: ", b)
    return True

def firewall_check_3(dicts):
    '''Returns True if all three firewall options have remote access disabled'''
    #TEST: Run as Admin - netsh advfirewall firewall set rule group="Windows Defender Firewall Remote Management" new enable=no
    for dic in dicts:
        if dic['RemoteManagement'] != 'Disable':
            return False
    return True

def firewall_check_4():
    return True

def firewall_check_5():
    return True