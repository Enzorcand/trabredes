from __future__ import annotations

import socket
import sys

from protocolo import ErroProtocolo, LeitorDeLinhas, codificar_bytes, decodificar

HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 5000


def receber_uma_mensagem(sock: socket.socket, leitor: LeitorDeLinhas):
    while True:
        linhas = leitor.alimentar(sock.recv(4096))
        if linhas:
            return decodificar(linhas[0])


def autenticar(sock: socket.socket, leitor: LeitorDeLinhas) -> str:
    usuario = input("Usuario: ")
    senha = input("Senha: ")
    sock.sendall(codificar_bytes("LOGIN", usuario, senha))

    resposta = receber_uma_mensagem(sock, leitor)
    if resposta.tipo == "LOGIN_OK":
        print(f">> Login aceito. Bem-vindo, {usuario}!")
        return usuario
    motivo = resposta.campos[0] if resposta.campos else "motivo desconhecido"
    print(f">> Login rejeitado: {motivo}")
    sys.exit(1)


def loop_interativo(sock: socket.socket, leitor: LeitorDeLinhas, usuario: str) -> None:
    print("Digite mensagens de chat, ou '/set k v', '/get k', '/bye' para saír.")
    while True:
        try:
            linha = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            linha = "/bye"

        if not linha:
            continue

        if linha == "/bye":
            sock.sendall(codificar_bytes("BYE"))
            print(">> Encerrando sessao.")
            break

        if linha.startswith("/set "):
            partes = linha.split(" ", 2)
            if len(partes) < 3:
                print(">> uso: /set <chave> <valor>")
                continue
            _, chave, valor = partes
            sock.sendall(codificar_bytes("CMD", "SET", chave, valor))

        elif linha.startswith("/get "):
            _, chave = linha.split(" ", 1)
            sock.sendall(codificar_bytes("CMD", "GET", chave.strip()))

        else:
            sock.sendall(codificar_bytes("MSG", usuario, linha))

        resposta = receber_uma_mensagem(sock, leitor)
        if resposta.tipo in ("CMD_OK", "MSG_OK"):
            if resposta.campos:
                print(f">> ok: {resposta.campos[0]}")
        elif resposta.tipo in ("CMD_ERR", "ERR"):
            motivo = resposta.campos[0] if resposta.campos else "erro"
            print(f">> erro: {motivo}")


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else HOST_PADRAO
    porta = int(sys.argv[2]) if len(sys.argv) > 2 else PORTA_PADRAO

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, porta))
        print(f"Conectado a {host}:{porta} (SRCP em texto claro)")
        leitor = LeitorDeLinhas()

        try:
            usuario = autenticar(sock, leitor)
            loop_interativo(sock, leitor, usuario)
        except ErroProtocolo as exc:
            print(f"Erro de protocolo: {exc}")
        except (ConnectionResetError, BrokenPipeError):
            print("Conexao com o servidor foi perdida.")


if __name__ == "__main__":
    main()
