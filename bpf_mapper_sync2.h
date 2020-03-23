#ifndef __BPF_MAPPER_SYNC2_H
#define __BPF_MAPPER_SYNC2_H

#define	MAP_PREFIX	"/sys/fs/bpf/tc/globals"
#define CT_MAP "CT_MAP_TCP4"

const char* jsonStr = "{'saddr':'%s', 'sport':%d, 'daddr':'%s', 'dport':%d, 'rx_packets':%lld, 'rx_bytes':%lld, 'tx_packets':%lld, 'tx_bytes':%lld, 'lifetime':%d, 'rx_closing':%d, 'tx_closing':%d, 'seen_non_sync':%d, 'tx_flags_seen':%d, 'rx_flags_seen':%d, 'last_tx_report':%d, 'last_rx_report':%d}";

struct ipv4_ct_tuple {
    __be32	daddr;
    __be32	saddr;
    __be16	sport;
    __be16	dport;
    __u8  nexthdr;
    __u8  flags;
};

struct ct_entry {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u32 lifetime;
    __u16 rx_closing:1,
          tx_closing:1,
          seen_non_syn:1,
          reserved:9;

    __u8  tx_flags_seen;
    __u8  rx_flags_seen;

    __u32 last_tx_report;
    __u32 last_rx_report;
};

struct kafka_msg {
	char *saddr;
	uint16_t sport;
	char *daddr;
	uint16_t dport;
    struct ct_entry *entry;
};

#endif
