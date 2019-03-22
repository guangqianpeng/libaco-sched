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
#include "aco_assert_override.h"

char buf[65536];

void session() {
    app_config_t* config = aco_get_arg();

    while(1) {
        int64_t err;
        aco_read_timeout(config->fd, buf, sizeof(buf), 10000, &err);
        if (err != ACO_OK) {
            break;
        }
    }
    aco_socket_close(config->fd);
    aco_exit();
}

int main() {
    app_config_t config;
    aco_config_init(&config);

    config.type = APP_NETWORK_CLIENT;
    config.task_pool_size = 1;
    config.name = "chargen-client";
    config.ip = "0.0.0.0";
    config.port = 2007;
    config.connection_func = session;
    config.log_level = ACO_LOG_LEVEL_DEBUG;

    app_template_run(&config);
}

