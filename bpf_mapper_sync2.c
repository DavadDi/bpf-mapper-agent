#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include "bpf.h"
#include "bpf_mapper_sync2.h"
#include "kafka.h"

static volatile sig_atomic_t running = 1;

static void stop(int sig){
	running = 0;
}

static int map_get(char *map_name) {
	char pinned_file[256];
	snprintf(pinned_file, sizeof(pinned_file), "%s/%s", MAP_PREFIX, map_name);
	return bpf_obj_get(pinned_file);
}

static char* int_to_ip(uint32_t num){
	char *ipstr = (char *)malloc(15);
	uint32_t nums[4];
    for (int i=0;i<4;i++){
        nums[i] = (num>>((3-i)*8))&0xFF;
    }
	snprintf(ipstr, 15, "%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3]);
	return ipstr;
}

static bool lookup_map_by_last_key(
		int map_fd,
		struct ipv4_ct_tuple *last_key,
		struct ipv4_ct_tuple *key,
		char * msg_str){

	if(bpf_map_get_next_key(map_fd, (void *)last_key, (void *)key) < 0){
		fprintf(stderr, "error when get next key: %s\n", strerror(errno));
		return false;
	}

	struct ct_entry map_entry = {};
	if(bpf_map_lookup_elem(map_fd, (void*)key, (void*) &map_entry) < 0){
		fprintf(stderr, "error when lookup map value: %s\n", strerror(errno));
		return false;
	}

	snprintf(msg_str, 400, jsonStr,
			int_to_ip(htonl(key->saddr)),
			htons(key->sport),
			int_to_ip(htonl(key->daddr)),
			htons(key->dport),
			map_entry.rx_packets,
			map_entry.rx_bytes,
			map_entry.tx_packets,
			map_entry.tx_bytes,
			map_entry.lifetime,
			map_entry.rx_closing,
			map_entry.tx_closing,
			map_entry.seen_non_syn,
			map_entry.tx_flags_seen,
			map_entry.rx_flags_seen,
			map_entry.last_tx_report,
			map_entry.last_rx_report);
	fprintf(stdout, "%s\n", msg_str);

	return true;
}

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "%% Usage: %s <broker> <topic>\n", argv[0]);
		return 1;
	}
	kafka_brokers = argv[1];
	kafka_topic = argv[2];
	rd_kafka_t * rk = create_kafka_inst(kafka_brokers);
	if(rk == NULL){
		fprintf(stderr, "could not create kafka producer\n");
		return 1;
	}

	int map_fd = -1;
	map_fd = map_get(CT_MAP);
	if (map_fd < 0) {
		fprintf(stderr, "could not find map %s: %s\n", CT_MAP, strerror(errno));
		return 1;
	}

	signal(SIGINT, stop);

	while(running){
		struct ipv4_ct_tuple *key = (struct ipv4_ct_tuple *) malloc(sizeof(struct ipv4_ct_tuple));
		struct ipv4_ct_tuple *next_key = (struct ipv4_ct_tuple *) malloc(sizeof(struct ipv4_ct_tuple));
		while (true){
			char curr_msg[400];
			bool is_succ = lookup_map_by_last_key(map_fd, key, next_key, (char *) curr_msg);
			if(!is_succ){
				break;
			}

			send_message(rk, curr_msg);
			memcpy(key, next_key, sizeof(struct ipv4_ct_tuple));
		}

		free(key);
		free(next_key);

		sleep(1);
	}

	close(map_fd);
	close_kafka_inst(rk);
}
