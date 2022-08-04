import win32evtlog
import xml.etree.ElementTree as ET

#channel = 'Microsoft-Windows-Windows Defender/Operational'
#channel = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'

channel = 'Microsoft-Windows-PushNotification-Platform/Operational'


def on_event(action, context, event_handle):
    print("CAUGHT EVENT")
    if action == win32evtlog.EvtSubscribeActionDeliver:
        xml = ET.fromstring(win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml))
        # xml namespace, root element has a xmlns definition, so we have to use the namespace
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

        event_id = xml.find(f'.//{ns}EventID').text
        level = xml.find(f'.//{ns}Level').text
        channel = xml.find(f'.//{ns}Channel').text
        execution = xml.find(f'.//{ns}Execution')
        process_id = execution.get('ProcessID')
        thread_id = execution.get('ThreadID')
        time_created = xml.find(f'.//{ns}TimeCreated').get('SystemTime')
        print(f'Time: {time_created}, Level: {level} Event Id: {event_id}, Channel: {channel}, Process Id: {process_id}, Thread Id: {thread_id}')
        print(xml.find(f'.//{ns}Data').text)
        print()

handle = win32evtlog.EvtSubscribe(
    channel,
    win32evtlog.EvtSubscribeToFutureEvents,
    None,
    Callback = on_event)

# Wait for user to hit enter...
input()

win32evtlog.CloseEventLog(handle)