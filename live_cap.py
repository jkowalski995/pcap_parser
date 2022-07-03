import pyshark


def live_cap(inter, res=None):
    capt = pyshark.LiveCapture(inter)
    for packet in capt:
        if "UDP" in packet:
            if res is None:
                res = ''
            res += (
                f'[PROTOCOL]: {packet.highest_layer} [SRC IP]: {packet.ip.src} [DST IP]: {packet.ip.dst} [SRC MAC]: '
                f'{packet.eth.src} [DST MAC]: {packet.eth.dst}\n')
            print(res)


while True:
    try:
        live_cap('wlp2s0')
    except (KeyboardInterrupt, EOFError):
        print("Exit...")
        break
