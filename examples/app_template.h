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

#ifndef APP_TEMPLATE_H
#define APP_TEMPLATE_H

#include "aco_log.h"
#include "aco_scheduler.h"

typedef enum {
    APP_NETWORK_SERVER,
    APP_NETWORK_CLIENT,
    APP_OTHER,
} app_type_t;

typedef struct {
    app_type_t     type;

    // maximum tasks in proccess
    size_t         task_pool_size;

    // app name
    char*          name;

    // for server and client app
    char*          ip;
    int            port;
    int            fd;
    aco_msec_t     timeout;
    aco_cofuncp_t  connection_func;

    // for other app
    aco_cofuncp_t  main_func;

    // all app type can run background tasks
    size_t         bg_func_n;
    aco_cofuncp_t  bg_func[1024];

    size_t         sstk_size;

    // debug
    aco_log_level_t  log_level;

} app_config_t;

void aco_config_init(app_config_t* config) {
    memset(config, 0, sizeof(app_config_t));
}

static inline
void server_handler() {
    app_config_t* config = aco_get_arg();

    int fd = aco_accept_socket(config->ip, config->port);
    if (fd < 0) {
        aco_exit();
    }

    config->fd = fd;

    for (size_t i = 1; ; i++) {
        int conn_fd = aco_accept(fd);
        if (conn_fd < 0) {
            aco_log_info("retry accept() after 1 second...");
            aco_sleep(1000);
            continue;
        }

        char name[32];
        snprintf(name, sizeof(name), "%lu-fd-%d", i, conn_fd);

        aco_log_info("connection {%s} up", name);

        aco_tid_t tid = aco_launch_task(config->connection_func, 
                                        (void*)(int64_t)conn_fd, NULL, name);
        aco_assert(tid.tid >= 0);
    }
}


static inline
void client_handler() {
    app_config_t* config = aco_get_arg();
    
    int fd = aco_connect(config->ip, config->port, 3, 1000);
    if (fd < 0) {
        aco_exit();
    }

    config->fd = fd;

    aco_log_info("connection {%s} up", aco_get_name());

    // the handler should exit itself
    config->connection_func();
}

static inline
void app_template_run(app_config_t* config) {

    // libaco required this...
    aco_thread_init(NULL);
    aco_t* main_co = aco_create(NULL, NULL, 0, NULL, NULL);
    
    // set log level
    g_aco_log_level = config->log_level;

    // network application should ignore SIGPIPE
    if (config->type == APP_NETWORK_SERVER || 
        config->type == APP_NETWORK_CLIENT) {
        signal(SIGPIPE, SIG_IGN);
    }


    // create scheduler
    aco_sched_t* sched = aco_sched_create(config->task_pool_size);

    // background tasks    
    for (size_t i = 0; i < config->bg_func_n; i++) {

        aco_share_stack_t* sstk = aco_share_stack_new(0);
        aco_t* co = aco_create(main_co, sstk, 0, config->bg_func[i], &config);
        aco_share_stack_unref(sstk);

        char name[32];
        snprintf(name, sizeof(name), "background-%lu", i + 1);

        aco_sched_co(sched, co, name);
    }

    // main task
    aco_share_stack_t* sstk = aco_share_stack_new(0);
    aco_t* co = NULL;

    switch (config->type) {
    case APP_NETWORK_SERVER:
        co = aco_create(main_co, sstk, 0, server_handler, config);
        break;
    case APP_NETWORK_CLIENT:
        co = aco_create(main_co, sstk, 0, client_handler, config);
        break;    
    case APP_OTHER:
        co = aco_create(main_co, sstk, 0, config->main_func, config);
        break;
    default:
        aco_assert(0);
    }

    aco_share_stack_unref(sstk);
    aco_sched_co(sched, co, config->name);

    aco_sched_loop(sched);
    aco_sched_destroy(sched);
    aco_destroy(main_co);
}

#endif

