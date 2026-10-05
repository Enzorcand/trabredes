from __future__ import annotations

import socket
import struct
import sys
from datetime import datetime

from protocolo import ErroProtocolo, decodificar

ETH_P_ALL = 0x0003  
PORTA_PADRAO = 5000

TIPOS_SENSIVEIS = {"LOGIN", "MSG", "CMD"}


def log(msg: str) -> None:
    agora = datetime.now().strftime("%H:%M:%S")
    print(f"[{agora}] {msg}")


def parse_cabecalho_ip(pacote: bytes):
    """Decodifica o cabecalho IPv4 (20 bytes fixos) de `pacote`.

    Retorna (ihl_bytes, protocolo, ip_origem, ip_destino).
    """
    cabecalho = pacote[:20]
    campos = struct.unpack("!BBHHHBBH4s4s", cabecalho)
    versao_ihl = campos[0]
    ihl = (versao_ihl & 0x0F) * 4
    protocolo = campos[6]
    ip_origem = socket.inet_ntoa(campos[8])
    ip_destino = socket.inet_ntoa(campos[9])
    return ihl, protocolo, ip_origem, ip_destino


def parse_cabecalho_tcp(segmento: bytes):
    """Decodifica o cabecalho TCP (minimo 20 bytes) de `segmento`.

    Retorna (porta_origem, porta_destino, tamanho_cabecalho_tcp, flags).
    """
    cabecalho = segmento[:20]
    campos = struct.unpack("!HHLLBBHHH", cabecalho)
    porta_origem = campos[0]
    porta_destino = campos[1]
    offset_flags = campos[4]
    tamanho_cabecalho_tcp = (offset_flags >> 4) * 4
    flags = campos[5]
    return porta_origem, porta_destino, tamanho_cabecalho_tcp, flags


def flags_tcp_para_texto(flags: int) -> str:
    nomes = []
    if flags & 0x01:
        nomes.append("FIN")
    if flags & 0x02:
        nomes.append("SYN")
    if flags & 0x04:
        nomes.append("RST")
    if flags & 0x08:
        nomes.append("PSH")
    if flags & 0x10:
        nomes.append("ACK")
    if flags & 0x20:
        nomes.append("URG")
    return ",".join(nomes) if nomes else "-"


def processar_payload(payload: bytes, origem: str, destino: str) -> None:
    if not payload:
        return

    texto = payload.decode("utf-8", errors="replace")
    for linha in texto.splitlines():
        linha = linha.strip()
        if not linha:
            continue
        try:
            msg = decodificar(linha)
        except ErroProtocolo:
            log(f"{origem} -> {destino} | (payload nao reconhecido) {linha!r}")
            continue

        if msg.tipo in TIPOS_SENSIVEIS:
            log(f"{origem} -> {destino} | *** {msg.tipo} capturado em texto claro: {msg.campos} ***")
        else:
            log(f"{origem} -> {destino} | {msg.tipo} {msg.campos}")


def rodar_sniffer(porta_alvo: int, interface: str | None = None) -> None:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    if interface:
        sock.bind((interface, 0))
    log(
        f"sniffer de aplicacao iniciado na interface "
        f"{interface or '(todas)'}, filtrando porta {porta_alvo} (Ctrl+C para parar)"
    )

    try:
        while True:
            pacote_bruto, _ = sock.recvfrom(65535)

            ethertype = struct.unpack("!H", pacote_bruto[12:14])[0]
            if ethertype != 0x0800:
                continue  

            pacote_ip = pacote_bruto[14:]
            ihl, protocolo, ip_origem, ip_destino = parse_cabecalho_ip(pacote_ip)
            if protocolo != 6:
                continue

            segmento_tcp = pacote_ip[ihl:]
            porta_origem, porta_destino, tam_tcp, flags = parse_cabecalho_tcp(segmento_tcp)

            if porta_origem != porta_alvo and porta_destino != porta_alvo:
                continue

            payload = segmento_tcp[tam_tcp:]
            origem = f"{ip_origem}:{porta_origem}"
            destino = f"{ip_destino}:{porta_destino}"

            if payload:
                processar_payload(payload, origem, destino)
            else:
                log(f"{origem} -> {destino} | pacote TCP [{flags_tcp_para_texto(flags)}] sem payload")

    except KeyboardInterrupt:
        log("sniffer interrompido pelo usuario (Ctrl+C)")
    finally:
        sock.close()


def main() -> None:
    interface: str | None = None
    porta = PORTA_PADRAO

    args = sys.argv[1:]
    if len(args) == 1:
        if args[0].isdigit():
            porta = int(args[0])
        else:
            interface = args[0]
    elif len(args) >= 2:
        interface = args[0]
        porta = int(args[1])

    if sys.platform != "linux":
        print(
            "AVISO: este sniffer usa AF_PACKET/SOCK_RAW, disponivel apenas em "
            "Linux. Execute-o na VM-observador (Linux) do laboratorio.\n"
            "Prosseguindo mesmo assim -- a chamada abaixo deve falhar neste SO."
        )

    try:
        rodar_sniffer(porta, interface)
    except PermissionError:
        print(
            "Erro de permissao: sockets raw exigem privilegio de root. "
            "Execute com: sudo python3 sniffer.py [interface] [porta]"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
