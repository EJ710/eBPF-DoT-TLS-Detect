#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>  // UDP header
#include <linux/ipv6.h> // IPv6 support
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#define MAX_PAYLOAD_SIZE 128

struct event_data {
    __u8 payload[MAX_PAYLOAD_SIZE];
    __u32 payload_len;
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} payload_map SEC(".maps");

static __always_inline int block_plain_dns(struct xdp_md *ctx, void *data, void *data_end) {
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Block IPv4 DNS
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return XDP_PASS;

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udp = data + sizeof(*eth) + (iph->ihl * 4);
            if (data + sizeof(*eth) + (iph->ihl * 4) + sizeof(*udp) > data_end)
                return XDP_PASS;
                
            if (udp->dest == bpf_htons(53) || udp->source == bpf_htons(53)) {
                return XDP_DROP;  // Block DNS packet
            }
        }
    }
    // Block IPv6 DNS
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
            return XDP_PASS;

        if (ip6h->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip6h);
            if (data + sizeof(*eth) + sizeof(*ip6h) + sizeof(*udp) > data_end)
                return XDP_PASS;
                
            if (udp->dest == bpf_htons(53) || udp->source == bpf_htons(53)) {
                return XDP_DROP;  // Block DNS packet
            }
        }
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_capture_payload(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Block plaintext DNS first
    int dns_action = block_plain_dns(ctx, data, data_end);
    if (dns_action != XDP_PASS) {
        return dns_action;  // Drop DNS packets immediately
    }
    
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }
    
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    
    int ip_header_len = ip->ihl * 4;
    if (ip_header_len < 20 || ip_header_len > 60) {
        return XDP_PASS;
    }
    
    struct tcphdr *tcp = (void *)ip + ip_header_len;
    if ((void *)tcp + sizeof(*tcp) > data_end) {
        return XDP_PASS;
    }
    
    int tcp_header_len = tcp->doff * 4;
    if (tcp_header_len < 20 || tcp_header_len > 60) {
        return XDP_PASS;
    }
    
    void *payload = (void *)tcp + tcp_header_len;
    if (payload > data_end) {
        return XDP_PASS;
    }
    
    __u32 payload_len = (__u32)(data_end - payload);
    
    // Skip packets with no payload or very small payload
    if (payload_len == 0 || payload_len < 5) {
        return XDP_PASS;
    }
    
    // Filter for TLS ports
    __u16 dest_port = bpf_ntohs(tcp->dest);
    __u16 src_port = bpf_ntohs(tcp->source);
    
    if (dest_port != 443 && src_port != 443 && 
        dest_port != 993 && src_port != 993 &&    // IMAPS
        dest_port != 995 && src_port != 995 &&    // POP3S
        dest_port != 8443 && src_port != 8443 &&  // Test server
        dest_port != 8080 && src_port != 8080 &&  // Alt HTTP/HTTPS
        dest_port != 9443 && src_port != 9443) {   // Alt HTTPS
        return XDP_PASS;
    }
    
    // Check if it looks like TLS handshake or HTTP
    __u8 first_byte, second_byte;
    if (payload + 1 >= data_end) {
        return XDP_PASS;
    }
    
    first_byte = *(__u8 *)payload;
    second_byte = *(__u8 *)(payload + 1);
    
    int is_tls = (first_byte == 0x16 && second_byte == 0x03);
    int is_http = (first_byte == 'G' || first_byte == 'P' || first_byte == 'H'); // GET, POST, HTTP
    
    if (!is_tls && !is_http) {
        return XDP_PASS;
    }
    
    if (payload_len > MAX_PAYLOAD_SIZE) {
        payload_len = MAX_PAYLOAD_SIZE;
    }
    
    struct event_data evt = {};
    evt.src_ip = ip->saddr;
    evt.dest_ip = ip->daddr;
    evt.src_port = src_port;
    evt.dest_port = dest_port;
    evt.payload_len = payload_len;
    
    int copy_len = payload_len < MAX_PAYLOAD_SIZE ? payload_len : MAX_PAYLOAD_SIZE;
    for (int i = 0; i < copy_len && i < MAX_PAYLOAD_SIZE; i++) {
        if (payload + i >= data_end) {
            break;
        }
        evt.payload[i] = *(__u8 *)(payload + i);
    }
    
    bpf_perf_event_output(ctx, &payload_map, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
