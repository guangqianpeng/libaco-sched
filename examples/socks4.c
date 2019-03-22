// Copyright 2019 guangqianpeng <guangqian1994@foxmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "app_template.h"
#include "aco_stream.h"
#include "aco_time_wheel.h"
#include "aco_scheduler.h"
#include "aco_assert_override.h"

aco_time_wheel_t* wheel;

typedef struct half_relay_s half_relay_t;
typedef struct relay_s relay_t;

struct half_relay_s {
    relay_t*      relay;
    aco_stream_t* in;
    aco_stream_t* out;
    size_t        size;
    char*         buf;
};

struct relay_s {
    aco_queue_t   queue;
    half_relay_t  upstream;
    half_relay_t  downstream;
    int           closed;
};

relay_t* relay_create(aco_stream_t* client, aco_stream_t* server, size_t size) {
    relay_t* r = malloc(sizeof(relay_t));
    assertalloc_ptr(r);

    r->upstream.relay = r;
    r->upstream.in = client;
    r->upstream.out = server;
    r->upstream.size = size;
    r->upstream.buf = malloc(size);
    assertalloc_ptr(r->upstream.buf);

    r->downstream.relay = r;
    r->downstream.in = server;
    r->downstream.out = client;
    r->downstream.size = size;
    r->downstream.buf = malloc(size);
    assertalloc_ptr(r->downstream.buf);


    aco_queue_init(&r->queue);
    r->closed = 0;
    return r;
}

void relay_destroy(relay_t* r) {
    aco_stream_destroy(r->upstream.in);
    aco_stream_destroy(r->upstream.out);

    free(r->upstream.buf);
    free(r->downstream.buf);
    free(r);
}

void relay_close(relay_t* r) {
    if (!r->closed) {
        aco_stream_close(r->upstream.in);
        aco_stream_close(r->upstream.out);
        r->closed = 1;
    }
}

void relay_run() {
    half_relay_t* r = aco_get_arg();

    while(1) {
        size_t read_n = aco_stream_read_n(r->in, r->buf, r->size);

        if (r->in->result == ACO_ESYSTEM) {
            relay_close(r->relay);
            break;
        }

        aco_time_wheel_refresh_if_waiting(wheel, &r->relay->queue);

        if (r->in->result == ACO_EOF) {
            if (!r->relay->closed) {
                aco_stream_shutdown(r->out);
            }
            break;
        }

        assert(r->in->result == ACO_OK && read_n > 0);

        size_t write_n = aco_stream_write_n(r->out, r->buf, read_n);

        if (r->out->result == ACO_ESYSTEM) {
            relay_close(r->relay);
            break;
        }

        aco_time_wheel_refresh_if_waiting(wheel, &r->relay->queue);

        assert(r->out->result == ACO_OK && read_n == write_n);

        aco_yield(NULL);
    }
    aco_exit();
}

#define SOCKS4_TIMEOUT_SECOND  30
#define SOCKS4_TIMEOUT         (SOCKS4_TIMEOUT_SECOND * 1000)
#define SOCKS4_CONNECT_TIMEOUT (3 * 1000)
#define SOCKS4_CONNECT_RETRY   0
#define SOCKS4_BUF_SIZE        65536

static char SOCKS4_GRANTED[8] = {'\x00', '\x5a'};
static char SOCKS4_FAILED[8]  =  {'\x00', '\x5b'};

typedef struct {
    char vn;
    char cd;
    uint16_t dstport;
    uint32_t dstip;
} socks4_t;

#define CHECK(exp) do {\
    (exp); \
    if (s->result != ACO_OK) \
        return -1; \
} while(0)

int sock4_read(aco_stream_t* s, socks4_t* socks) {
   
    char userid;

    CHECK(aco_stream_read_8(s, &socks->vn));
    CHECK(aco_stream_read_8(s, &socks->cd));
    CHECK(aco_stream_read_16(s, &socks->dstport));
    CHECK(aco_stream_read_32(s, &socks->dstip));

    int see_null = 0;
    for (int i = 0; i < 256; i++) {
        CHECK(aco_stream_read_8(s, &userid));
        if (userid == 0) {
            see_null = 1;
            break;
        }
    }

    return see_null ? 0 : -1;
}

#define socks4_write(s, message) \
    aco_stream_write_n((s), (message), sizeof(message))

int socks4_connect(socks4_t* socks) {

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htobe16(socks->dstport);
    addr.sin_addr.s_addr = htobe32(socks->dstip);
    
    return aco_connect2(&addr, 
                        SOCKS4_CONNECT_RETRY, 
                        SOCKS4_CONNECT_TIMEOUT);
}

#define FINALIZE(msg) do {\
    aco_log_error("connection {%s} %s", aco_get_name(), msg);\
    socks4_write(s, SOCKS4_FAILED);\
    aco_stream_destroy(s);\
    aco_exit();\
} while(0)

void session() {
    int conn_fd = (int)(int64_t)aco_get_arg();
    
    aco_stream_t* s = aco_stream_create(conn_fd, 128, 0, SOCKS4_TIMEOUT);

    socks4_t rqst;
    if ((sock4_read(s, &rqst)) < 0) {
        FINALIZE("socks4_read() error");
    }

    int fd = socks4_connect(&rqst);
    if (fd < 0) {
        FINALIZE("sock4_connect() failed");
    }

    socks4_write(s, SOCKS4_GRANTED);
    
    aco_stream_set_timeout(s, 0);
    aco_stream_t* server = aco_stream_create(fd, 0, 0, 0);

    relay_t* r = relay_create(s, server, SOCKS4_BUF_SIZE);

    aco_log_info("session {%s} up", aco_get_name());

    aco_tid_t t1 = aco_launch_task(relay_run, &r->upstream, aco_co()->share_stack, "half-relay-1");
    aco_tid_t t2 = aco_launch_task(relay_run, &r->downstream, aco_co()->share_stack, "half-relay-2");

    assert(t1.tid >= 0 && t2.tid >= 0);

    aco_time_wheel_insert(wheel, &r->queue);

    aco_wait_task(t1);
    aco_wait_task(t2);

    aco_log_info("session {%s} down", aco_get_name());

    aco_time_wheel_remove_if_waiting(wheel, &r->queue);

    relay_destroy(r);
    aco_exit();
}

void timeout_handler(aco_queue_t* data) {
    relay_t* r = aco_queue_data(data, relay_t, queue);
    aco_log_info("session timeout, now close", aco_get_name());
    relay_close(r);
}

void timeout_driver() {
    while(1) {
        aco_sleep(1000);
        aco_time_wheel_run(wheel);
    }
}

int main() {

    wheel = aco_time_wheel_create(SOCKS4_TIMEOUT_SECOND, timeout_handler);

    app_config_t config;
    aco_config_init(&config);

    config.type = APP_NETWORK_SERVER;
    config.task_pool_size = 1024;
    config.name = "sock4-proxy";
    config.ip = "0.0.0.0";
    config.port = 9527;
    config.connection_func = session;
    config.bg_func_n = 1;
    config.bg_func[0] = timeout_driver;
    config.log_level = ACO_LOG_LEVEL_ERROR;

    app_template_run(&config);

    aco_time_wheel_destroy(wheel);
}
