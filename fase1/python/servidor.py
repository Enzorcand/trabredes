"""
Uso:
    python servidor.py [host] [porta]

Padrao: host=0.0.0.0, porta=5000
"""

from __future__ import annotations

import socket
import sys
import threading
from datetime import datetime
from typing import Dict

from protocolo import (
    ErroProtocolo,
    LeitorDeLinhas,
    codificar_bytes,
    decodificar,
)

HOST_PADRAO = "0.0.0.0"
PORTA_PADRAO = 5000

USUARIOS: Dict[str, str] = {
    "alice": "senha123",
    "bob": "trab123",
    "admin": "admin123",
}

REPOSITORIO: Dict[str, str] = {}
LOCK_REPOSITORIO = threading.Lock()


def log(msg: str) -> None:
    agora = datetime.now().strftime("%H:%M:%S")
    print(f"[{agora}] {msg}")


def tratar_login(msg, sock: socket.socket) -> str | None:
    """Processa LOGIN|usuario|senha. Retorna o usuario autenticado ou None."""
    if len(msg.campos) < 2:
        sock.sendall(codificar_bytes("ERR", "LOGIN requer usuario e senha"))
        return None

    usuario, senha = msg.campos[0], msg.campos[1]
    log(f"tentativa de login: usuario={usuario!r} senha={senha!r}")

    if USUARIOS.get(usuario) == senha:
        sock.sendall(codificar_bytes("LOGIN_OK", usuario))
        log(f"usuario {usuario!r} autenticado com sucesso")
        return usuario

    sock.sendall(codificar_bytes("LOGIN_ERR", "usuario ou senha invalidos"))
    log(f"login invalido para usuario={usuario!r}")
    return None


def tratar_msg(msg, sock: socket.socket, usuario: str) -> None:
    if len(msg.campos) < 2:
        sock.sendall(codificar_bytes("ERR", "MSG requer usuario e texto"))
        return
    remetente, texto = msg.campos[0], SEPARADOR_SEGURO(msg.campos[1:])
    log(f"[chat] {remetente}: {texto}")
    sock.sendall(codificar_bytes("MSG_OK"))


def SEPARADOR_SEGURO(campos) -> str:
    return "|".join(campos)


def tratar_cmd(msg, sock: socket.socket, usuario: str) -> None:
    if not msg.campos:
        sock.sendall(codificar_bytes("CMD_ERR", "comando vazio"))
        return

    nome = msg.campos[0].upper()
    args = msg.campos[1:]

    if nome == "SET" and len(args) >= 2:
        chave, valor = args[0], "|".join(args[1:])
        with LOCK_REPOSITORIO:
            REPOSITORIO[chave] = valor
        log(f"[cmd] {usuario} SET {chave}={valor!r}")
        sock.sendall(codificar_bytes("CMD_OK", f"{chave} definido"))

    elif nome == "GET" and len(args) >= 1:
        chave = args[0]
        with LOCK_REPOSITORIO:
            valor = REPOSITORIO.get(chave)
        log(f"[cmd] {usuario} GET {chave} -> {valor!r}")
        if valor is None:
            sock.sendall(codificar_bytes("CMD_ERR", f"chave {chave} nao encontrada"))
        else:
            sock.sendall(codificar_bytes("CMD_OK", valor))

    else:
        sock.sendall(codificar_bytes("CMD_ERR", f"comando desconhecido: {nome}"))


def atender_cliente(conexao: socket.socket, endereco) -> None:
    leitor = LeitorDeLinhas()
    usuario_autenticado: str | None = None
    log(f"nova conexao de {endereco}")

    try:
        with conexao:
            while True:
                dados = conexao.recv(4096)
                if not dados:
                    log(f"conexao encerrada por {endereco}")
                    break

                try:
                    linhas = leitor.alimentar(dados)
                except ErroProtocolo as exc:
                    conexao.sendall(codificar_bytes("ERR", str(exc)))
                    break

                for linha in linhas:
                    try:
                        msg = decodificar(linha)
                    except ErroProtocolo as exc:
                        conexao.sendall(codificar_bytes("ERR", str(exc)))
                        continue

                    if msg.tipo == "LOGIN":
                        usuario_autenticado = tratar_login(msg, conexao) or usuario_autenticado
                    elif msg.tipo == "MSG":
                        if usuario_autenticado is None:
                            conexao.sendall(codificar_bytes("ERR", "faca LOGIN antes de enviar MSG"))
                        else:
                            tratar_msg(msg, conexao, usuario_autenticado)
                    elif msg.tipo == "CMD":
                        if usuario_autenticado is None:
                            conexao.sendall(codificar_bytes("ERR", "faca LOGIN antes de enviar CMD"))
                        else:
                            tratar_cmd(msg, conexao, usuario_autenticado)
                    elif msg.tipo == "BYE":
                        log(f"cliente {endereco} ({usuario_autenticado}) disse BYE")
                        return
                    else:
                        conexao.sendall(codificar_bytes("ERR", f"tipo desconhecido: {msg.tipo}"))
    except (ConnectionResetError, BrokenPipeError):
        log(f"conexao com {endereco} perdida abruptamente")


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else HOST_PADRAO
    porta = int(sys.argv[2]) if len(sys.argv) > 2 else PORTA_PADRAO

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((host, porta))
        servidor.listen()
        log(f"servidor SRCP escutando em {host}:{porta} (protocolo em TEXTO CLARO)")

        try:
            while True:
                conexao, endereco = servidor.accept()
                thread = threading.Thread(
                    target=atender_cliente, args=(conexao, endereco), daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            log("servidor interrompido pelo usuario (Ctrl+C)")


if __name__ == "__main__":
    main()
