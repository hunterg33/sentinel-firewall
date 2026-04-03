content = open('src/ids/packet_engine.py').read()

old = 'from src.event_bus import event_bus, Event, EventType, Severity'

new = '''from src.event_bus import event_bus, Event, EventType, Severity

_PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}'''

old2 = 'pkt.protocol = str(ip_layer.proto)'
new2 = 'pkt.protocol = _PROTO_NAMES.get(ip_layer.proto, str(ip_layer.proto))'

content = content.replace(old, new, 1)
content = content.replace(old2, new2, 1)

open('src/ids/packet_engine.py', 'w').write(content)
print('Done')