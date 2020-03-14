#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "bpf.h"

#define	MAP_PREFIX	"/sys/fs/bpf/tc/globals"
#define CT_MAP "CT_MAP_TCP4"

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

int map_get(char *map_name) {
	char pinned_file[256];
	snprintf(pinned_file, sizeof(pinned_file), "%s/%s", MAP_PREFIX, map_name);
	return bpf_obj_get(pinned_file);
}

void init_key(struct ipv4_ct_tuple *key) {
	key->saddr = 0;
	key->sport = 0;
	key->daddr = 0;
	key->dport = 0;
	key->flags = 0;
	key->nexthdr = 0;
}

void copy_key(struct ipv4_ct_tuple *key, struct ipv4_ct_tuple *next_key){
	key->saddr = next_key->saddr;
	key->sport = next_key->sport;
	key->daddr = next_key->daddr;
	key->dport = next_key->dport;
	key->flags = next_key->flags;
	key->nexthdr = next_key->nexthdr;

	next_key->saddr = 0;
	next_key->sport = 0;
	next_key->daddr = 0;
	next_key->dport = 0;
	next_key->flags = 0;
	next_key->nexthdr = 0;
}

char* int_to_ip(uint32_t num){
	char *ipstr = (char *)malloc(15);
	uint32_t nums[4];
    for (int i=0;i<4;i++){
        nums[i] = (num>>((3-i)*8))&0xFF;
    }
	snprintf(ipstr, 15, "%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3]);
	return ipstr;
}

int main(int argc, char **argv) {
	int map_fd = -1;

	map_fd = map_get(CT_MAP);
	if (map_fd < 0) {
		fprintf(stderr, "could not find map %s: %s\n", CT_MAP, strerror(errno));
		return 1;
	}

	struct ipv4_ct_tuple *key;
	struct ipv4_ct_tuple *next_key;

	key = (struct ipv4_ct_tuple *) malloc(sizeof(struct ipv4_ct_tuple));
	init_key(key);
	next_key = (struct ipv4_ct_tuple *) malloc(sizeof(struct ipv4_ct_tuple));
	init_key(next_key);

	struct ct_entry *map_entry = (struct ct_entry *) malloc(sizeof(struct ct_entry));

	while (true){
		if(bpf_map_get_next_key(map_fd, (void *)key, (void *)next_key) < 0){
			fprintf(stderr, "error when get next key: %s\n", strerror(errno));
			break;
		}

		if(bpf_map_lookup_elem(map_fd, (void*)next_key, (void*)map_entry) < 0){
			fprintf(stderr, "error when lookup map value: %s\n", strerror(errno));
			break;
		}

		fprintf(stdout, "Key: srcIP=%s, srcPort=%d, dstIP=%s, dstPort=%d; "
				+ "Entry: tx_packets=%lld, rx_packets=%lld\n",
				int_to_ip(htonl(next_key->saddr)),
				htons(next_key->sport),
				int_to_ip(htonl(next_key->daddr)),
				htons(next_key->dport),
				map_entry->tx_packets,
				map_entry->rx_packets);

		copy_key(key, next_key);
	}

	free(key);
	free(next_key);
	free(map_entry);
	close(map_fd);
}
