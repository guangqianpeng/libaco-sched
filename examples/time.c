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
    int fd = (int)(int64_t)aco_get_arg();

    aco_stream_t* s = aco_stream_create(fd, 0, 0, 1000);
    aco_stream_write_32(s, (uint32_t)time(NULL));

    aco_stream_destroy(s);
    aco_exit();
}

int main() {
    app_config_t config;
    aco_config_init(&config);

    config.type = APP_NETWORK_SERVER;
    config.task_pool_size = 1024;
    config.name = "time";
    config.ip = "0.0.0.0";
    config.port = 2007;
    config.connection_func = session;
    config.log_level = ACO_LOG_LEVEL_DEBUG;

    app_template_run(&config);
}

