#ifndef __KAFKA_H
#define __KAFKA_H

#include <librdkafka/rdkafka.h>

const char *brokers, *topic;

rd_kafka_t * create_kafka_inst(const char *brokers);
void close_kafka_inst(rd_kafka_t *rk);
void send_message(rd_kafka_t *rk, char *buf);

#endif
