[![Build Status](https://travis-ci.com/guangqianpeng/libaco-sched.svg?token=5Qb7a23qwthf2XSMwmia&branch=master)](https://travis-ci.com/guangqianpeng/libaco-sched)

A coroutine scheduler and lightweight network library for [libaco](https://github.com/hnes/libaco).

# Introduction

libaco-sched is a N:1 cooperative multi-task library, which enables you to build single threaded network applications easily.

# Install

```shell
git clone https://github.com/guangqianpeng/libaco-sched
cd libaco-sched
mkdir build && cd build
cmake .. && make && make install
```

# Example

Here is a simple echo server which handles at most 1024 concurrent TCP connections:

```c
#include "app_template.h"
#include "aco_assert_override.h"

void session() {
    // get connection socket
    int fd = (int)(int64_t)aco_get_arg();
    
    // create echo buffer
    char buf[65536];

    while(1) {
        int64_t err;
		
        // read data
        size_t read_n = aco_read_timeout(fd, buf, sizeof(buf), 10000, &err);
        if (err != ACO_OK) {
            break;
        }
		
        // write data
        size_t write_n = aco_write(fd, buf, read_n, &err);
        if (err != ACO_OK) {
            break;
        }

        assert(read_n == write_n);
    }
    aco_socket_close(fd);
    aco_exit();
}

int main() {
    app_config_t config;
    aco_config_init(&config);

    config.type = APP_NETWORK_SERVER;
    config.name = "echo";
    
    // set maximum concurrent tasks in the process
    config.task_pool_size = 1024;
    
    // listen 0.0.0.0:2007
    config.ip = "0.0.0.0";
    config.port = 2007;
    
    // use session() to handle connection sockets
    config.connection_func = session;
    
    // log level: debug, info, error
    config.log_level = ACO_LOG_LEVEL_DEBUG;

    // start running
    app_template_run(&config);
}
```

A more complex example is here: [socks4 proxy](<https://github.com/guangqianpeng/libaco-sched/blob/master/examples/socks4.c>).