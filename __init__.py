from turtle import update
import win32evtlog
import xml.etree.ElementTree as ET
from extras import print_tests_colour, Colours
from checks import Check
import os
import time

from xml.etree.ElementTree import ElementTree
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import SubElement


def run_report():

    print("=== Status Report")
    checks_list = []
    i = 1
    checks_list.append(Check.check_1())
    checks_list.append(Check.check_2())
    checks_list.append(Check.check_3())
    checks_list.append(Check.check_4())
    checks_list.append(Check.check_5())
    checks_list.append(Check.check_6())
    checks_list.append(Check.check_7())
    checks_list.append(Check.check_8())
    checks_list.append(Check.check_9())

    for check in checks_list:
        print_tests_colour(i, check)
        i += 1
    print("==========")

relevant_ids = {
    "2003": "A Windows Defender Firewall setting has changed.",
    "2005": "A rule has been modified in the Windows Defender Firewall exception list.",
    "2008": "Windows Defender Firewall Group Policy settings have changed. The new settings have been applied.",
    "4738": "A user account was changed.",
    "4732": "A member was added to a security-enabled local group.",
    "4735": "A security-enabled local group was changed.",
    "4663": "An attempt was made to access an object.",
    "4657": "A registry value was modified.",
    "5136": "A directory service object was modified."
    #"4656": "A handle to an object was requested."
    #4656, 4660, 4663, 4670
}

events = []

def on_event(action, context, event_handle):
    global report_needed

    if action == win32evtlog.EvtSubscribeActionDeliver:
        #print(win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml))
        my_xml = ET.fromstring(win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml))
        tree = ElementTree(my_xml)
        with open('person.xml', 'w') as f:
            tree.write(f, encoding='unicode')

        # xml namespace, root element has a xmlns definition, so we have to use the namespace
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
        event_id = my_xml.find(f'.//{ns}EventID').text
        #obj_name = my_xml[1][6].text
        #obj = my_xml.find(f'.//{ns}EventData')
        #test = obj.find(f'.//{ns}')
        #print("obj: ", obj_name)
        #input()
        

        if event_id in relevant_ids:
            #os.system('cls')
            print(f"{Colours.RED}CAUGHT EVENT " + event_id + f": {Colours.DEFAULT}" + relevant_ids[event_id])
            report_needed = True
            #run_report()

def update_report():
    time.sleep(5)
    global report_needed
    if report_needed:
        report_needed = False
        run_report()


 

if __name__ == "__main__":
    
    handle1 = win32evtlog.EvtSubscribe(
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
        win32evtlog.EvtSubscribeToFutureEvents,
        None,
        Callback = on_event)

    handle2 = win32evtlog.EvtSubscribe(
        'Security',
        win32evtlog.EvtSubscribeToFutureEvents,
        None,
        Callback = on_event)
    
    global report_needed
    report_needed = False

    try:
        run_report()
        while True:
            update_report()
            #print("report_needed: ", report_needed)
    except KeyboardInterrupt:
        print("Exiting...")
        win32evtlog.CloseEventLog(handle1)
        win32evtlog.CloseEventLog(handle2)
        exit()