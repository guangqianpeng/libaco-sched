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

#include <sys/time.h>

#include "app_template.h"
#include "aco_time_wheel.h"
#include "aco_assert_override.h"

#define TIMEOUT_SECOND 5
#define TOTAL_ITEMS    100

aco_baton_t       stop;
aco_time_wheel_t* wheel;

aco_msec_t now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

typedef struct {
    aco_queue_t queue;
    int64_t     value;
    aco_msec_t  when;
} item_t;

item_t* item_create(int64_t value) {
   item_t* item = malloc(sizeof(item_t));
   item->value = value;
   aco_queue_init(&item->queue);
   item->when = now();
   return item;
}

void item_destroy(item_t* item) {
    free(item);
}

void time_wheel_driver() {
    while (aco_baton_wait_timeout(&stop, 1000) == ACO_ETIMEOUT) {
        aco_time_wheel_run(wheel);
    }

    while(wheel->total > 0) {
        aco_sleep(1000);
        aco_time_wheel_run(wheel);
    }

    aco_exit();
}

void timeout_handler(aco_queue_t* data) {
    item_t* item = aco_queue_data(data, item_t, queue);
    fprintf(stderr, "<-item[%ld] diff %ld ms\n", 
            item->value, 
            now() - item->when - TIMEOUT_SECOND * 1000);
    item_destroy(item);
}

void session() {
    for (int64_t i = 1; i < TOTAL_ITEMS; i++) {
        item_t* item = item_create(i);

        fprintf(stderr, "->item[%ld]\n", i);        
        aco_time_wheel_insert(wheel, &item->queue);
        aco_sleep(100);
    }
    aco_baton_post(&stop);
    aco_exit();
}

int main() {
    aco_baton_init(&stop);
    wheel = aco_time_wheel_create(TIMEOUT_SECOND, timeout_handler);

    app_config_t config;
    aco_config_init(&config);

    config.type = APP_OTHER;
    config.task_pool_size = 2;
    config.name = "time-wheel";
    config.main_func = session;
    config.bg_func[0] = time_wheel_driver;
    config.bg_func_n = 1;
    config.log_level = ACO_LOG_LEVEL_INFO;

    app_template_run(&config);

    aco_time_wheel_destroy(wheel);
    aco_baton_destroy(&stop);
}

