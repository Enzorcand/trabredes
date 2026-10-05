# Fase 1 — Reconhecimento e escuta passiva

Implementação em Python do serviço alvo (protocolo próprio em texto claro,
**SRCP** — *Simple Rede Chat Protocol*) e do interceptador passivo (sniffer
de aplicação), conforme o enunciado do trabalho de Laboratório de Redes de
Computadores ("Interceptação e Defesa de um Protocolo de Aplicação").

> **Uso restrito ao laboratório isolado da disciplina.** O sniffer usa
> socket raw e só deve ser executado contra o tráfego gerado pelo próprio
> serviço alvo deste repositório, dentro das VMs do grupo.

## Arquivos

| Arquivo        | Papel                                                                 |
|-----------------|------------------------------------------------------------------------|
| `protocolo.py`  | Definição do protocolo SRCP (formato das mensagens, codec, framing). |
| `servidor.py`   | Servidor TCP: login, chat e repositório chave-valor em texto claro.  |
| `cliente.py`    | Cliente TCP interativo que fala o protocolo SRCP.                    |
| `sniffer.py`    | Interceptador passivo (socket raw) que lê o tráfego e extrai dados.  |
| `gerar_pdf_relatorio.py` | Converte `RELATORIO.md` em `RELATORIO_FASE1.pdf` (requer `reportlab`, veja `requirements.txt`). |

## O protocolo SRCP

Mensagens são linhas ASCII terminadas em `\n`, no formato
`TIPO|campo1|campo2|...`. Tipos principais:

- `LOGIN|usuario|senha` → autenticação (**em texto claro**, de propósito).
- `LOGIN_OK|usuario` / `LOGIN_ERR|motivo`
- `MSG|usuario|texto` → mensagem de chat sem cifragem.
- `CMD|SET|chave|valor` / `CMD|GET|chave` → repositório chave-valor sem proteção.
- `BYE` → encerra a sessão.

Detalhes completos em [`protocolo.py`](python/protocolo.py).

## Topologia sugerida (3 VMs)

```
          rede isolada (ex.: rede host-only / NAT interno do hypervisor)
┌───────────────┐        ┌───────────────┐        ┌───────────────────┐
│  VM-cliente    │  TCP   │  VM-servidor   │        │  VM-observador     │
│  cliente.py    │◄──────►│  servidor.py   │        │  sniffer.py        │
│                │  :5000 │                │        │  (modo promíscuo)  │
└───────────────┘        └───────────────┘        └───────────────────┘
                                                         ▲
                                   todo o tráfego da rede │ é visível aqui
                                   (switch em modo espelhado/hub virtual)
```

- **VM-servidor**: roda `servidor.py`, escutando em `0.0.0.0:5000`.
- **VM-cliente**: roda `cliente.py <ip-do-servidor> 5000`.
- **VM-observador**: na mesma rede isolada, roda `sniffer.py <interface> 5000`
  com privilégio de root, capturando o tráfego entre cliente e servidor.
  Para que o observador veja o tráfego, a rede virtual deve permitir
  captura promíscua (ex.: rede "interna"/"host-only" do VirtualBox/VMware
  com a opção de modo promíscuo habilitada na interface, ou um hub virtual
  em vez de um switch que isole o tráfego).

## Como executar

### 1. Servidor (VM-servidor)

```bash
python servidor.py 0.0.0.0 5000
```

Usuários de teste já cadastrados em `servidor.py` (`USUARIOS`):
`alice/senha123`, `bob/trab123`, `admin/admin123`.

### 2. Cliente (VM-cliente)

```bash
python cliente.py <ip-do-servidor> 5000
```

Fluxo interativo:

```
Usuario: alice
Senha: senha123
>> Login aceito. Bem-vindo, alice!
> ola servidor, isso é um teste
> /set cor azul
> /get cor
> /bye
```

### 3. Sniffer (VM-observador, Linux, com root)

```bash
sudo python3 sniffer.py eth0 5000
```

O sniffer abre um socket raw (`AF_PACKET`/`SOCK_RAW`), filtra os pacotes
TCP cuja porta de origem ou destino seja `5000`, remonta o payload da
camada de aplicação e decodifica as mensagens SRCP, destacando no console
as credenciais (`LOGIN`), mensagens de chat (`MSG`) e comandos (`CMD`)
capturados em texto claro.

> **Nota de portabilidade:** `AF_PACKET` é específico do Linux. Rode o
> sniffer na VM-observador com Linux. Em paralelo, o Wireshark pode (e é
> sugerido pelo enunciado) ser usado como instrumento de apoio para
> validar a captura durante o desenvolvimento.

## Captura de evidência com Wireshark

1. Abra o Wireshark na VM-observador, selecione a interface da rede
   isolada e aplique o filtro `tcp.port == 5000`.
2. Execute o fluxo cliente/servidor descrito acima.
3. Localize no Wireshark os pacotes com dados (`Follow > TCP Stream`) e
   anote os números dos pacotes onde aparecem `LOGIN|...`, `MSG|...` e
   `CMD|...` em texto legível — esses números alimentam o relatório
   (`RELATORIO.md`).

## Limitações desta fase (propositais)

- Sem cifragem: qualquer um na rede lê tudo (resolvido na Fase 3 com TLS).
- Sem integridade: nada impede alterar os dados em trânsito (Fase 2 explora
  isso com um proxy MITM; Fase 3 corrige).
- Autenticação fraca: senha comparada em texto claro no servidor (Fase 3
  deve trocar por hash).
