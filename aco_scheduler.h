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

#ifndef ACO_SCHED_H
#define ACO_SCHED_H

#include <stdint.h>
#include <signal.h>
#include <netinet/in.h>

#include "aco.h"
#include "aco_queue.h"
#include "aco_rbtree.h"

#ifdef __cplusplus
extern "C" {
#endif

// ACO return value
#define ACO_OK       (0)
#define ACO_EOF      (-1) // read eof
#define ACO_ESYSTEM  (-2) // system call error (broken pipe, connection reset, etc.) 
#define ACO_ETIMEOUT (-3) // timeout
#define ACO_EINVALID (-4) // invalid argument


// internal
#define ACO_TASK_WAIT_TASK   1
#define ACO_TASK_WAIT_READ   2
#define ACO_TASK_WAIT_WRITE  4
#define ACO_TASK_WAIT_TIME   8
#define ACO_TASK_WAIT_BATON  16

#define ACO_EPOLL_MAX_FD     1024000
#define ACO_EPOLL_MAX_EVENTS 1024

typedef int64_t aco_msec_t;
typedef struct aco_sched_s aco_sched_t;

typedef union {
    int64_t tid;
    struct {
        int32_t use_count;
        int32_t index;
    };
} aco_tid_t;

typedef struct {
    int64_t     counter;
    aco_queue_t waiters;
} aco_baton_t;

typedef struct {
    aco_queue_t        queue;     // chain tasks in ready queue & free queue
    aco_queue_t        waiters;   // tasks that waiting this task to be done
    aco_rbtree_node_t  timer;     // put in rbtree to track timeout
    aco_tid_t          tid;
    aco_t*             co;
    int64_t            result;
    int                attached_fd;
    uint8_t            blocking;
    char               name[32];

    // debug
    const char*        yield_file;
    const char*        yield_func;
    int                yield_line;     
} aco_task_t;


aco_sched_t* aco_sched_create(size_t task_pool_size);
void aco_sched_destroy(aco_sched_t* sched);

aco_tid_t aco_sched_co(aco_sched_t* sched, aco_t* co, char* name);
void aco_sched_loop(aco_sched_t* sched);


aco_tid_t aco_launch_task(aco_cofuncp_t fp, void* arg, aco_share_stack_t* sstk, char* name);
int64_t aco_wait_task(aco_tid_t tid);
int64_t aco_wait_task_timeout(aco_tid_t tid, aco_msec_t timeout);


extern __thread aco_task_t* aco_gtls_task;
#define aco_get_tid()  ({(void)0; aco_gtls_task->tid;})
#define aco_get_name() ({(void)0; aco_gtls_task->name;})


void aco_sleep(aco_msec_t milliseconds);


size_t aco_read(int fd, void* buf, size_t count, int64_t* err);
size_t aco_read_timeout(int fd, void* buf, 
                         size_t count, aco_msec_t timeout, int64_t* err);


size_t aco_write(int fd, void* buf, size_t count, int64_t* err);
size_t aco_write_timeout(int fd, void* buf, 
                          size_t count, aco_msec_t timeout, int64_t* err);


int aco_accept_socket(const char* ip, int port);
int aco_accept(int fd);


int aco_connect2(struct sockaddr_in* addr, 
                 size_t retry_times, 
                 aco_msec_t timeout);
int aco_connect(const char* ip, int port, 
                size_t retry_times, 
                aco_msec_t timeout);


void aco_socket_nodelay(int fd, int on);
void aco_socket_shutdown(int fd);
void aco_socket_close(int fd);


void aco_baton_init(aco_baton_t* baton);
void aco_baton_destroy(aco_baton_t* baton);
void aco_baton_wait(aco_baton_t* baton);
int64_t aco_baton_wait_timeout(aco_baton_t* baton, aco_msec_t timeout);
void aco_baton_post(aco_baton_t* baton);


#ifdef __cplusplus
}
#endif

#endif

