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

void session() {
    int fd = (int)(int64_t)aco_get_arg();

    time_t seconds = time(NULL);
    struct tm tm_time;
    gmtime_r(&seconds, &tm_time);

    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d %02d %02d:%02d:%02d\n",
                       tm_time.tm_year + 1900, 
                       tm_time.tm_mon,
                       tm_time.tm_hour, 
                       tm_time.tm_min, 
                       tm_time.tm_sec);
    assert(len > 0);

    int64_t err;
    aco_write(fd, buf, (size_t)len, &err);

    aco_socket_close(fd);
    aco_exit();
}

int main() {
    app_config_t config;
    aco_config_init(&config);

    config.type = APP_NETWORK_SERVER;
    config.task_pool_size = 1024;
    config.name = "daytime";
    config.ip = "0.0.0.0";
    config.port = 2007;
    config.connection_func = session;
    config.log_level = ACO_LOG_LEVEL_DEBUG;

    app_template_run(&config);
}

