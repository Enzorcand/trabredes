from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

SEPARADOR = "|"
TERMINADOR = "\n"
ENCODING = "utf-8"

TAMANHO_MAX_LINHA = 8192


@dataclass
class Mensagem:
    """Representa uma mensagem decodificada do protocolo SRCP."""

    tipo: str
    campos: List[str] = field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - so para debug/log
        return codificar(self.tipo, *self.campos).rstrip(TERMINADOR)


class ErroProtocolo(Exception):
    """Levantada quando uma linha recebida nao segue o formato do protocolo."""


def codificar(tipo: str, *campos: str) -> str:
    if SEPARADOR in tipo:
        raise ErroProtocolo(f"tipo de mensagem invalido: {tipo!r}")
    partes = [tipo, *[str(c) for c in campos]]
    linha = SEPARADOR.join(partes) + TERMINADOR
    return linha


def codificar_bytes(tipo: str, *campos: str) -> bytes:
    return codificar(tipo, *campos).encode(ENCODING)


def decodificar(linha: str) -> Mensagem:
    linha = linha.rstrip("\r\n")
    if not linha:
        raise ErroProtocolo("linha vazia recebida")
    partes = linha.split(SEPARADOR)
    tipo = partes[0].strip()
    if not tipo:
        raise ErroProtocolo(f"mensagem sem tipo: {linha!r}")
    campos = partes[1:]
    return Mensagem(tipo=tipo, campos=campos)


class LeitorDeLinhas:
    def __init__(self) -> None:
        self._buffer = b""

    def alimentar(self, dados: bytes) -> List[str]:
        """Adiciona bytes recebidos do socket e retorna as linhas completas
        (decodificadas em texto) que ja puderam ser extraidas."""
        if not dados:
            return []
        self._buffer += dados
        if len(self._buffer) > TAMANHO_MAX_LINHA * 4:
            raise ErroProtocolo("buffer de entrada excedeu o tamanho maximo")

        linhas: List[str] = []
        while True:
            idx = self._buffer.find(b"\n")
            if idx == -1:
                break
            bruta, self._buffer = self._buffer[: idx + 1], self._buffer[idx + 1 :]
            linhas.append(bruta.decode(ENCODING, errors="replace"))
        return linhas
