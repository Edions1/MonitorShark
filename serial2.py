import pyshark

def process_packet(packet):
    try:
        # Extrai informações do pacote
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport
        packet_size = packet.length

        # Exibe as informações
        print(f"Src IP: {src_ip}, Src Port: {src_port}")
        print(f"Dst IP: {dst_ip}, Dst Port: {dst_port}")
        print(f"Packet Size: {packet_size} bytes")
        print("-" * 40)

    except AttributeError as e:
        # Ignora pacotes que não têm informações necessárias
        pass

# Interface de rede a ser monitorada (substitua 'eth0' pela sua interface)
interface = "wlan0"

# Captura pacotes da interface usando pyshark
capture = pyshark.LiveCapture(interface, display_filter="ip")

try:
    # Processa cada pacote capturado
    for packet in capture.sniff_continuously():
        process_packet(packet)

except KeyboardInterrupt:
    print("Captura encerrada pelo usuário.")
