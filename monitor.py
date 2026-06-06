#!/usr/bin/env python3
"""
monitor.py — Monitor de Latência TCP via eBPF (BCC)

Mede o RTT do handshake TCP (SYN → SYN-ACK) sem ferramentas de user-space,
e compara com os valores obtidos pelo ping ICMP.

Uso:
    sudo python3 monitor.py [--ping HOST] [--count N]

Exemplos:
    sudo python3 monitor.py
    sudo python3 monitor.py --ping google.com --count 5
    sudo python3 monitor.py --ping 8.8.8.8
"""

import argparse
import ctypes
import socket
import struct
import subprocess
import re
import sys
from collections import defaultdict
from bcc import BPF


# Estrutura de evento (deve espelhar rtt_event_t do C)
class RTTEvent(ctypes.Structure):
    _fields_ = [
        ("saddr",   ctypes.c_uint32),
        ("daddr",   ctypes.c_uint32),
        ("sport",   ctypes.c_uint16),
        ("dport",   ctypes.c_uint16),
        ("rtt_us",  ctypes.c_uint64),
    ]


def ip_to_str(addr: int) -> str:
    """Converte um inteiro de 32 bits (little-endian) para string IPv4."""
    return socket.inet_ntoa(struct.pack("I", addr))


# Callback chamado pelo perf buffer a cada novo evento BPF
# Acumula RTTs por IP de destino para o resumo final
rtt_samples: dict[str, list[float]] = defaultdict(list)

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(RTTEvent)).contents
    src   = ip_to_str(event.saddr)
    dst   = ip_to_str(event.daddr)
    rtt   = event.rtt_us / 1000.0          # converte µs → ms

    rtt_samples[dst].append(rtt)

    print(
        f"[TCP RTT] {src}:{event.sport} → {dst}:{event.dport}  "
        f"RTT = {rtt:.3f} ms"
    )


# Coleta RTT via ping ICMP para comparação
def run_ping(host: str, count: int = 5) -> list[float]:
    """Executa ping e devolve lista de RTTs em ms."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", host],
            capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        print("[AVISO] Comando 'ping' não encontrado.", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"[AVISO] ping para {host} excedeu o timeout.", file=sys.stderr)
        return []

    rtts = []
    # Extrai linhas "64 bytes from ...: icmp_seq=1 ttl=... time=X.XX ms"
    for line in result.stdout.splitlines():
        m = re.search(r"time=([0-9.]+)\s*ms", line)
        if m:
            rtts.append(float(m.group(1)))

    return rtts


def print_ping_comparison(host: str, count: int):
    """Imprime tabela comparando RTT TCP medido com ping ICMP."""
    print(f"\n{'─'*60}")
    print(f"  Comparação com ping ICMP → {host} ({count} pacotes)")
    print(f"{'─'*60}")

    ping_rtts = run_ping(host, count)
    if not ping_rtts:
        print("  Nenhum resultado de ping disponível.")
        return

    # Resolve o IP do host para casar com as amostras TCP
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        target_ip = host

    tcp_rtts = rtt_samples.get(target_ip, [])

    ping_avg = sum(ping_rtts) / len(ping_rtts)
    ping_min = min(ping_rtts)
    ping_max = max(ping_rtts)

    print(f"  ICMP ping  → min={ping_min:.3f} ms  avg={ping_avg:.3f} ms  max={ping_max:.3f} ms  ({len(ping_rtts)} amostras)")

    if tcp_rtts:
        tcp_avg = sum(tcp_rtts) / len(tcp_rtts)
        tcp_min = min(tcp_rtts)
        tcp_max = max(tcp_rtts)
        print(f"  TCP  eBPF  → min={tcp_min:.3f} ms  avg={tcp_avg:.3f} ms  max={tcp_max:.3f} ms  ({len(tcp_rtts)} amostras)")

        diff = tcp_avg - ping_avg
        print(f"\n  Diferença média (TCP − ICMP): {diff:+.3f} ms")
        print(
            "  Nota: RTT TCP inclui o tempo de processamento do SYN-ACK no\n"
            "  kernel local, por isso tende a ser ligeiramente maior que o\n"
            "  RTT ICMP puro."
        )
    else:
        print(f"  TCP  eBPF  → nenhuma amostra capturada para {target_ip}")
        print(
            f"  Dica: execute 'curl https://{host}' em outro terminal enquanto\n"
            f"  este monitor estiver rodando."
        )

    print(f"{'─'*60}\n")


def main():
    parser = argparse.ArgumentParser(description="Monitor de RTT TCP via eBPF")
    parser.add_argument(
        "--ping", metavar="HOST", default=None,
        help="Host para comparar com ping ICMP ao encerrar (ex.: google.com)"
    )
    parser.add_argument(
        "--count", metavar="N", type=int, default=5,
        help="Número de pacotes ping (padrão: 5)"
    )
    args = parser.parse_args()

    # Carrega o programa BPF
    bpf = BPF(src_file="tcp_rtt.c")

    # Anexa kprobes
    bpf.attach_kprobe(event="tcp_v4_connect",        fn_name="trace_tcp_connect")
    bpf.attach_kretprobe(event="tcp_v4_connect",    fn_name="trace_tcp_connect_ret")
    bpf.attach_kprobe(event="tcp_finish_connect",   fn_name="trace_tcp_finish_connect")

    # Registra o callback do perf buffer
    bpf["rtt_events"].open_perf_buffer(handle_event)

    print("╔══════════════════════════════════════════════════╗")
    print("║      Monitor de Latência TCP via eBPF (BCC)      ║")
    print("╚══════════════════════════════════════════════════╝")
    print("Aguardando conexões TCP de saída... (CTRL+C para sair)\n")
    if args.ping:
        print(f"Ao encerrar, será feita comparação com: ping {args.ping}\n")

    try:
        while True:
            # poll_events() processa eventos pendentes do perf buffer
            bpf.perf_buffer_poll(timeout=100)  # timeout em ms

    except KeyboardInterrupt:
        print("\nEncerrando monitor...")

    if rtt_samples:
        print(f"\n{'═'*60}")
        print("  Resumo das conexões TCP monitoradas:")
        print(f"{'═'*60}")
        for dst_ip, rtts in sorted(rtt_samples.items()):
            avg = sum(rtts) / len(rtts)
            print(
                f"  {dst_ip:>16}  →  "
                f"min={min(rtts):.3f} ms  avg={avg:.3f} ms  "
                f"max={max(rtts):.3f} ms  ({len(rtts)} conexões)"
            )
        print(f"{'═'*60}")
    else:
        print("\nNenhuma conexão TCP foi capturada.")

    # ── Comparação com ping ───────────────────────────────────────────────────
    if args.ping:
        print_ping_comparison(args.ping, args.count)


if __name__ == "__main__":
    main()