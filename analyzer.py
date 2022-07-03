import pyshark


def packets_count(dirr):
    """
    This function is used to count number of packets in the file.

    :param dirr: directory of the file
    :return: number of packets
    """

    pkt = pyshark.FileCapture(dirr)
    pkt.load_packets()
    count = len(pkt)
    return count


def show_info(dirr, protocol, info=None):
    """
    This function parse *.pcap file and show info about chosen protocol.

    :param dirr: directory of the file
    :param protocol: chosen protocol
    :param info: parsed info from file
    :return:
    """

    pkt = pyshark.FileCapture(dirr)
    pkt.load_packets()
    for idx, pk in enumerate(pkt):
        if protocol in pk:
            if info is None:
                info = ''
            info += (f"\nPacket {idx}\n" + str(pk) + "\n" + "Packet layers: " + str(pk.layers) +
                     "\n\n ------------------------------------------------------------------------------")
    return info

