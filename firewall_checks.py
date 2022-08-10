import subprocess
import re
from extras import Errors

class Firewall:

    @classmethod
    def __get_firewall_dict(cls, name):
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

    @classmethod
    def __get_all_firewall_dicts(cls):
        '''Returns a list of 3 dictionaries that correspond to the three types of firewall (Domain, Private, and Public), the dictionaries have the settings of the firewall'''
        return [cls.__get_firewall_dict("Domain"), cls.__get_firewall_dict("Private"), cls.__get_firewall_dict("Public")]

    @classmethod
    def firewall_check_1(cls):
        '''Returns OK if all three firewall options are enabled, False if at least one of them is not'''
        for dic in cls.__get_all_firewall_dicts():
            if dic['State'] == 'OFF':
                return Errors.FWC_01
        return Errors.OK

    @classmethod
    def firewall_check_2(cls):
        '''Returns OK if all three firewall options have remote access disabled'''
        #TEST: Run as Admin - netsh advfirewall firewall set rule group="Windows Defender Firewall Remote Management" new enable=no
        for dic in cls.__get_all_firewall_dicts():
            if dic['RemoteManagement'] != 'Disable':
                return Errors.FWC_02
        return Errors.OK