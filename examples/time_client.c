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

#include <time.h>

#include "aco_stream.h"
#include "app_template.h"
#include "aco_assert_override.h"

void session() {
    app_config_t* config = aco_get_arg();

    aco_stream_t* s = aco_stream_create(config->fd, 0, 0, 0);
    
    uint32_t data;
    aco_stream_read_32(s, &data);

    if (s->result == ACO_OK) {
        time_t seconds = (time_t)data;
        struct tm tm_time;
        gmtime_r(&seconds, &tm_time);

        fprintf(stderr, "%02d:%02d:%02d\n",
                tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
    }

    aco_stream_destroy(s);
    aco_exit();
}

int main() {
    app_config_t config;
    aco_config_init(&config);

    config.type = APP_NETWORK_CLIENT;
    config.task_pool_size = 1;
    config.name = "time-client";
    config.ip = "0.0.0.0";
    config.port = 2007;
    config.connection_func = session;
    config.log_level = ACO_LOG_LEVEL_DEBUG;

    app_template_run(&config);
}

