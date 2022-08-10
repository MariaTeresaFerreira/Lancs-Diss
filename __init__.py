from report import Report
import win32evtlog
import xml.etree.ElementTree as ET
import concurrent.futures
from elevate import elevate

paths = {
    "firewall": 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    "configs": "Security"
}

def on_firewall_event(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        print("caught firewall event")
        Report.firewall_report()

def on_configs_event(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        #print("caught configs event")
        xml = ET.fromstring(win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml))
        # xml namespace, root element has a xmlns definition, so we have to use the namespace
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

        event_id = xml.find(f'.//{ns}EventID').text
        if event_id != "4798" and event_id != "4799":
            print("EVENT ID: " + event_id)
            Report.configs_report()
            #print("dismiss event: id " + event_id)
            

if __name__ == "__main__":
    elevate()

    
    
    handle1 = win32evtlog.EvtSubscribe(
        paths['firewall'],
        win32evtlog.EvtSubscribeToFutureEvents,
        None,
        Callback = on_firewall_event)

    handle2 = win32evtlog.EvtSubscribe(
        paths['configs'],
        win32evtlog.EvtSubscribeToFutureEvents,
        None,
        Callback = on_configs_event)

    input()

    win32evtlog.CloseEventLog(handle1)
    win32evtlog.CloseEventLog(handle2)