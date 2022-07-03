import pyshark


def packets_count(dirr):
    pkt = pyshark.FileCapture(dirr)
    pkt.load_packets()
    count = len(pkt)
    return count


def show_info(dirr, protocol, info=None):
    pkt = pyshark.FileCapture(dirr)
    pkt.load_packets()
    for idx, pk in enumerate(pkt):
        if protocol in pk:
            if info is None:
                info = ''
            info += (f"\nPacket {idx}\n" + str(pk) + "\n" + "Packet layers: " + str(pk.layers) +
                     "\n\n ------------------------------------------------------------------------------")
    return info

