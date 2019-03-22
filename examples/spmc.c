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
#include "aco_scheduler.h"
#include "aco_assert_override.h"

// similar to glang's buffered channel
typedef struct {
    aco_baton_t readable;
    aco_baton_t writable;
    size_t      size;
    size_t      head;
    size_t      tail;
    int64_t     queue[];
} channel_t;

channel_t* channel_create(size_t size) {
    channel_t* ch = malloc(sizeof(channel_t) + size * sizeof(int64_t));

    ch->size = size;
    ch->head = 0;
    ch->tail = 0;

    aco_baton_init(&ch->readable);
    aco_baton_init(&ch->writable);

    for (size_t i = 0; i < size; i++) {
        aco_baton_post(&ch->writable);
    }

    return ch;
}

void channel_destroy(channel_t* ch) {
    aco_baton_destroy(&ch->readable);
    aco_baton_destroy(&ch->writable);
    free(ch);
}

void channel_put(channel_t* ch, int64_t value) {
    aco_baton_wait(&ch->writable);
    fprintf(stderr, "-> %03ld %s\n", value, aco_get_name());
    ch->queue[ch->tail] = value;
    ch->tail++;
    if (ch->tail >= ch->size) {
        ch->tail = 0;
    }
    aco_baton_post(&ch->readable);
}

int64_t channel_get(channel_t* ch) {
    aco_baton_wait(&ch->readable);
    int64_t value = ch->queue[ch->head];
    ch->head++;
    if (ch->head >= ch->size) {
        ch->head = 0;
    } else if (ch->head == ch->tail) {
        ch->head = 0;
        ch->tail = 0;
    }
    fprintf(stderr, "<- %03ld %s\n", value, aco_get_name());
    aco_baton_post(&ch->writable);
    return value;
}



#define CHANNEL_SIZE      1
#define N_CONSUMER        5 
#define ITEM_PER_CONSUMER 10

channel_t* ch;

void consumer() {
    aco_sleep(100);
    for (int i = 0; i < ITEM_PER_CONSUMER; i++) {
        channel_get(ch); 
    }
    aco_exit();
}

void producer() {
    int64_t total = N_CONSUMER * ITEM_PER_CONSUMER;
    for (int64_t i = 1; i <= total; i++) {
        channel_put(ch, i);
    }
    aco_exit();
}

int main() {
    ch = channel_create(CHANNEL_SIZE);

    app_config_t config;
    aco_config_init(&config);

    config.type = APP_OTHER;
    config.task_pool_size = N_CONSUMER + 1;
    config.name = "spmc";
    config.main_func = producer;
    config.log_level =  ACO_LOG_LEVEL_INFO;

    config.bg_func_n = N_CONSUMER;
    for (int i = 0; i < N_CONSUMER; i++) {
        config.bg_func[i] = consumer;
    }

    app_template_run(&config);

    channel_destroy(ch);
}

