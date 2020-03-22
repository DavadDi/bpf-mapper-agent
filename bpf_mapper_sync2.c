#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "bpf.h"
#include "bpf_mapper_sync2.h"

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

static void init_key(struct ipv4_ct_tuple *key){
	struct ipv4_ct_tuple tmp = {};
	key = &tmp;
}

static bool lookup_map_by_last_key(
		int map_fd,
		struct ipv4_ct_tuple *last_key,
		struct ipv4_ct_tuple *key,
		struct kafka_msg* my_msg){

	if(bpf_map_get_next_key(map_fd, (void *)last_key, (void *)key) < 0){
		fprintf(stderr, "error when get next key: %s\n", strerror(errno));
		return false;
	}

	struct ct_entry map_entry = {};
	if(bpf_map_lookup_elem(map_fd, (void*)key, (void*) &map_entry) < 0){
		fprintf(stderr, "error when lookup map value: %s\n", strerror(errno));
		return false;
	}

	struct kafka_msg tmp_msg = {
		.saddr = int_to_ip(htonl(key->saddr)),
		.sport = htons(key->sport),
		.daddr = int_to_ip(htonl(key->daddr)),
		.dport = htons(key->dport),
		.entry = &map_entry,
	};
	my_msg= &tmp_msg;
	return true;
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

	init_key(key);
	while (true){
		init_key(next_key);
		struct kafka_msg* curr_msg;
		bool is_succ = lookup_map_by_last_key(map_fd, key, next_key, curr_msg);
		if(!is_succ){
			break;
		}
		key = next_key;
	}

	close(map_fd);
}
