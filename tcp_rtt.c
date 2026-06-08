#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// 4-tupla com endereço e porta de origem e destino
struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// Evento enviado para o user-space com a 4-tupla e o RTT calculado
struct rtt_event_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 rtt_us;
};

// Mapa auxiliar: associa o ponteiro do socket à struct sock*
// para recuperar o socket no kretprobe (que não recebe argumentos).
BPF_HASH(sock_store, u64, u64);  // pid_tgid → sk_ptr

// Mapa principal do tipo Hash para armazenar o timestamp do SYN indexado pela 4-tupla (flow_key_t).
BPF_HASH(start, struct flow_key_t, u64);

// Mapa de saída do tipo Perf Event Array para enviar os eventos de RTT para o user-space.
BPF_PERF_OUTPUT(rtt_events);


// Usa tcp_v4_connect para pegar o socket e o timestamp do início da conexão, pois é chamado antes do kernel escolher o IP de origem.
// O tcp_v4_connect é uma função de kernel chamada quando um processo inicia uma conexão TCP IPv4. 
// Ela é responsável por preparar o socket e escolher o IP de origem, mas ainda não estabeleceu a conexão.

// Kpobre e Kretprobe são usados para instrumentar funções do kernel. O kprobe é acionado quando a função é chamada,
//  e o kretprobe é acionado quando a função retorna. 


// kprobe:tcp_v4_connect
// Neste ponto o saddr ainda é 0, então apenas guardamos o ponteiro do socket
// indexado pelo pid_tgid para recuperar no kretprobe.
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 sk_ptr = (u64)sk;
    sock_store.update(&pid_tgid, &sk_ptr);
    return 0;
}

// kretprobe:tcp_v4_connect
// Chamado após tcp_v4_connect retornar. O kernel já escolheu o IP de origem
// e preencheu skc_rcv_saddr.
int trace_tcp_connect_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Se tcp_v4_connect retornou erro, ignora
    int ret = PT_REGS_RC(ctx);
    if (ret != 0)
        goto cleanup;

    u64 *sk_ptr = sock_store.lookup(&pid_tgid);
    if (sk_ptr == 0)
        goto cleanup;

    struct sock *sk = (struct sock *)(*sk_ptr);

    struct flow_key_t key = {};
    bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&key.sport, sizeof(key.sport), &sk->__sk_common.skc_num);

    u16 dport_be = 0;
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);
    key.dport = ntohs(dport_be);

    u64 ts = bpf_ktime_get_ns();
    start.update(&key, &ts);

cleanup:
    sock_store.delete(&pid_tgid);
    return 0;
}

// kprobe:tcp_finish_connect
// Chamado quando o SYN-ACK chega e a conexão entra em TCP_ESTABLISHED.
// Reconstrói a mesma 4-tupla para recuperar os dados no mapa e calcular o RTT.
int trace_tcp_finish_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    struct flow_key_t key = {};
    bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&key.sport, sizeof(key.sport), &sk->__sk_common.skc_num);

    u16 dport_be = 0;
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);
    key.dport = ntohs(dport_be);

    u64 *tsp = start.lookup(&key);
    if (tsp == 0)
        return 0;

    u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    start.delete(&key);

    struct rtt_event_t event = {};
    event.saddr  = key.saddr;
    event.daddr  = key.daddr;
    event.sport  = key.sport;
    event.dport  = key.dport;
    event.rtt_us = delta_us;

    rtt_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}