import pyshark


def cap():
    capt = pyshark.LiveCapture("wlp2s0")
    for packet in capt:
        # print(packet.ip.src)
        # print(packet.eth.src)
        # print(packet.udp.srcport)
        # print(packet.ip.dst)
        # print(packet.eth.dst)
        # print(packet.udp.dstport)
        # print(packet.layers)
        try:
            print(packet.tcp.srcport)
        except AttributeError:
            continue


# cap()

def live_cap(inter, layer_2_prot, layer_3_prot):
    capt = pyshark.LiveCapture(inter)
    try:
        for packet in capt:
            print(f"ETH SRC: {packet.eth.src}\n")
            print(f"ETH DST: {packet.eth.dst}\n")
            if layer_2_prot == "IP":
                print(f"IP SRC: {packet.ip.src}")
                print(f"IP DST: {packet.ip.dst}")
            elif layer_2_prot == "ARP":
                print("ARP")
            if layer_3_prot == "UDP":
                print(f"UDP SRC PORT: {packet.udp.srcport}")
                print(f"UDP DST PORT: {packet.udp.dstport}")
            elif layer_3_prot == "TCP":
                print(f"TCP SRC PORT: {packet.tcp.srcport}")
                print(f"TCP DST PORT: {packet.tcp.dstport}")
    except AttributeError:
        pass


# while True:
#     live_cap('wlp2s0', 'IP', 'UDP')

def live_cap(inter, res=None):
    capt = pyshark.LiveCapture(inter)
    for packet in capt:
        if "IP" in packet:
            if res is None:
                res = ''
            res = (
                f'[PROTOCOL]: {packet.highest_layer} [SRC IP]: {packet.ip.src} [DST IP]: {packet.ip.dst} [SRC MAC]: '
                f'{packet.eth.src} [DST MAC]: {packet.eth.dst}')
            return res


while True:
    print(live_cap('wlp2s0'))
