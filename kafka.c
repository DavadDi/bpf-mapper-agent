#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "kafka.h"

static void direct_msg_callback(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
	if (rkmessage->err) {
		fprintf(stderr, "%% Message delivery failed: %s\n", rd_kafka_err2str(rkmessage->err));
	} else {
		fprintf(stderr, "%% Message delivered (%zd bytes, partition %"PRId32")\n", rkmessage->len, rkmessage->partition);
	}
}

rd_kafka_t * create_kafka_inst(const char *brokers){
	rd_kafka_t *rk;

	char errstr[512];

	rd_kafka_conf_t *conf = rd_kafka_conf_new();

	if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%s\n", errstr);
		return NULL;
	}

	rd_kafka_conf_set_dr_msg_cb(conf, direct_msg_callback);

	rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!rk) {
		fprintf(stderr, "%% Failed to create new producer: %s\n", errstr);
		return NULL;
	}

	return rk;
}

void close_kafka_inst(rd_kafka_t *rk) {
	/* Wait for final messages to be delivered or fail.
	 * rd_kafka_flush() is an abstraction over rd_kafka_poll() which waits for all messages to be delivered. */
	fprintf(stderr, "%% Flushing final messages..\n");
	rd_kafka_flush(rk, 10 * 1000 /* wait for max 10 seconds */);

	if (rd_kafka_outq_len(rk) > 0) {
		fprintf(stderr, "%% %d message(s) were not delivered\n", rd_kafka_outq_len(rk));
	}
	rd_kafka_destroy(rk);
}

void send_message(rd_kafka_t *rk, char *buf){
	size_t len = strlen(buf);
	rd_kafka_resp_err_t err;

retry:
	err = rd_kafka_producev(
		rk, // Producer handle
		RD_KAFKA_V_TOPIC(kafka_topic),  // Topic name
		RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),  // Make a copy of the payload.
		RD_KAFKA_V_VALUE(buf, len),  // Message value and length
		RD_KAFKA_V_OPAQUE(NULL),  // Per-Message opaque, provided in delivery report callback as msg_opaque.
		RD_KAFKA_V_END);  // End sentinel

	if (err) {
		fprintf(stderr, "%% Failed to produce to topic %s: %s\n", kafka_topic, rd_kafka_err2str(err));
		if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
			rd_kafka_poll(rk, 1000);
			goto retry;
		}
	} else {
		fprintf(stderr, "%% Enqueued message (%zd bytes) for topic %s\n", len, kafka_topic);
	}

	rd_kafka_poll(rk, 0);
}
