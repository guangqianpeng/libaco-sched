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

#define _GNU_SOURCE          

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <alloca.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "aco_scheduler.h"
#include "aco_log.h"
#include "aco_assert_override.h"


typedef void (*aco_sys_call_t)(aco_sched_t* sched,
                               aco_task_t* task);

typedef struct {
    aco_task_t* read_task;
    aco_task_t* write_task;
} attached_task_t;

typedef struct {
    int fd;
    size_t size;
    struct epoll_event events[ACO_EPOLL_MAX_EVENTS];
    attached_task_t tasks[ACO_EPOLL_MAX_FD];
} aco_epoll_t;

// at most one scheduler per thread
struct aco_sched_s {
    aco_task_t*       task_pool;
    size_t            task_pool_size;

    aco_queue_t       free_tasks;
    size_t            free_task_n;

    aco_queue_t       ready_tasks;

    aco_rbtree_t      time_tasks;
    aco_rbtree_node_t sentinel;

    aco_epoll_t       io_tasks;

    aco_msec_t        current_msec;
};

void aco_baton_init(aco_baton_t* baton) {
    baton->counter = 0;
    aco_queue_init(&baton->waiters);
}

void aco_baton_destroy(aco_baton_t* baton) {
    assert(aco_queue_empty(&baton->waiters));
}

#define aco_tid_to_ptr(arg) (void*)((arg).tid)
static aco_tid_t aco_ptr_to_tid(void* ptr) {
     aco_tid_t tid = {(int64_t)ptr};
     return tid;
}
static aco_tid_t aco_invalid_tid() {
    aco_tid_t tid = {-1};
    return tid;
}

#ifdef  __x86_64__
    _Static_assert(sizeof(aco_tid_t) == 8, "require 'sizeof(aco_tid_t) == 8'");
#else
    #error "platform no support yet"
#endif


static 
void aco_epoll_init(aco_epoll_t* ep) {
    ep->fd = epoll_create1(EPOLL_CLOEXEC);
    assert(ep->fd >= 0);
    ep->size = 0;
    bzero(ep->events, sizeof(ep->events));
    bzero(ep->tasks, sizeof(ep->tasks));
}

static 
void aco_epoll_free(aco_epoll_t* ep) {
    close(ep->fd);
}

static 
void aco_epoll_add(aco_epoll_t* ep, int fd, int op, uint32_t events) {
    struct epoll_event ee;
    ee.events = events;
    ee.data.u64 = 0; // make valgrind happy
    ee.data.fd = fd;
    int ret = epoll_ctl(ep->fd, op, fd, &ee);
    assert(ret == 0); (void)ret;
    ep->size++;
}

static 
void aco_epoll_add_read(aco_epoll_t* ep, int fd, aco_task_t* task) {
    attached_task_t* p = &ep->tasks[fd];

    assert(p->read_task == NULL);
    p->read_task = task;
    task->attached_fd = fd;

    if (p->write_task == NULL) {
        aco_epoll_add(ep, fd, EPOLL_CTL_ADD, EPOLLIN);
    } else {
        aco_epoll_add(ep, fd, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
    }
}

static 
void aco_epoll_add_write(aco_epoll_t* ep, int fd, aco_task_t* task) {
    attached_task_t* p = &ep->tasks[fd];

    assert(p->write_task == NULL);
    p->write_task = task;
    task->attached_fd = fd;

    if (p->read_task == NULL) {
        aco_epoll_add(ep, fd, EPOLL_CTL_ADD, EPOLLOUT);
    } else {
        aco_epoll_add(ep, fd, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
    }
}

static 
void aco_epoll_del(aco_epoll_t* ep, int fd, int op, uint32_t events) {
    struct epoll_event ee;
    ee.events = events;
    ee.data.u64 = 0; // make valgrind happy
    ee.data.fd = fd;
    int ret = epoll_ctl(ep->fd, op, fd, &ee);
    assert(ret == 0); (void)ret;
    ep->size--;
}


static 
void aco_epoll_del_read(aco_epoll_t* ep, int fd) {
    attached_task_t* p = &ep->tasks[fd];

    assert(p->read_task != NULL);
    assert(p->read_task->blocking & ACO_TASK_WAIT_READ);
    assert(p->read_task->attached_fd == fd);

    p->read_task->attached_fd = -1;
    p->read_task = NULL;

    if (p->write_task == NULL) {
        aco_epoll_del(ep, fd, EPOLL_CTL_DEL, 0);
    } else {
        aco_epoll_del(ep, fd, EPOLL_CTL_MOD, EPOLLOUT);
    }
}

static 
void aco_epoll_del_write(aco_epoll_t* ep, int fd) {
    attached_task_t* p = &ep->tasks[fd];

    assert(p->write_task != NULL);
    assert(p->write_task->blocking & ACO_TASK_WAIT_WRITE);
    assert(p->write_task->attached_fd == fd);

    p->write_task->attached_fd = -1;
    p->write_task = NULL;

    if (p->read_task == NULL) {
        aco_epoll_del(ep, fd, EPOLL_CTL_DEL, 0);
    } else {
        aco_epoll_del(ep, fd, EPOLL_CTL_MOD, EPOLLIN);
    }
}

static 
int aco_epoll_wait(aco_epoll_t* ep, int timeout) {
    while (1) {
        int ret = epoll_wait(ep->fd, ep->events, 
                             ACO_EPOLL_MAX_EVENTS, 
                             timeout);
        if (ret < 0) {
            if (errno != EINTR) {
                aco_log_sys("epoll_wait()");
            }
        } else { 
            return ret; 
        }
    }
}

static __thread aco_sched_t* aco_gtls_sched = NULL;
static __thread void*        aco_gtls_args[6];

__thread aco_task_t*  aco_gtls_task = NULL;


static 
void aco_task_init(aco_task_t* task, aco_t* co, char* name) {
    task->co = co;
    task->result = ACO_OK;
    task->tid.use_count++;
    task->yield_file = "init";
    task->yield_func = "init";
    task->yield_line = 0;
    if (name == NULL) {
        snprintf(task->name, sizeof(task->name), "aco-%d-%d", 
                 task->tid.index, task->tid.use_count);
    } else {
        snprintf(task->name, sizeof(task->name), "%s", name);
    }
}

static 
void* aco_task_run(aco_task_t* task) {
    aco_log_debug("resume task {%s} at %s:%d", 
                    task->name, 
                    task->yield_file, 
                    task->yield_line);
    return aco_resume(task->co, (void*)task->result);
}

static 
int aco_task_is_free(aco_task_t* task) {
    return task->co == NULL;
}

static 
int aco_sched_has_free_tasks(aco_sched_t* sched) {
    return !aco_queue_empty(&sched->free_tasks);
}

static 
int aco_sched_has_ready_tasks(aco_sched_t* sched) {
    return !aco_queue_empty(&sched->ready_tasks);
}

static 
int aco_sched_has_io_tasks(aco_sched_t* sched) {
    return sched->io_tasks.size > 0;
}

static 
int aco_sched_has_timer_tasks(aco_sched_t* sched) {
    return sched->time_tasks.size > 0;
}

static 
void aco_sched_update_time(aco_sched_t* sched) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    sched->current_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

aco_sched_t* aco_sched_create(size_t task_pool_size) {
    assert(aco_gtls_sched == NULL);
    assert(task_pool_size > 0);

    aco_sched_t* sched = malloc(sizeof(aco_sched_t));
    assertalloc_ptr(sched);

    aco_queue_init(&sched->ready_tasks);

    aco_epoll_init(&sched->io_tasks);

    aco_rbtree_init(&sched->time_tasks, &sched->sentinel);

    aco_task_t* pool = calloc(task_pool_size, sizeof(aco_task_t));
    assertalloc_ptr(pool);

    sched->task_pool = pool;
    sched->task_pool_size = task_pool_size;

    aco_queue_init(&sched->free_tasks);
    sched->free_task_n = task_pool_size;
    for (size_t i = 0; i < task_pool_size; i++) {
        aco_task_t* task = &pool[i];
        aco_queue_push_back(&sched->free_tasks, &task->queue);
        aco_queue_init(&task->waiters);
        pool[i].tid.index = i;
        pool[i].attached_fd = -1;
    }

    aco_sched_update_time(sched);

    aco_gtls_sched = sched;
    return sched;
}

void aco_sched_destroy(aco_sched_t* sched) {
    assertptr(aco_gtls_sched);
    assert(aco_gtls_sched == sched);

    // assert no task is running
    assert(!aco_sched_has_ready_tasks(sched));
    assert(!aco_sched_has_io_tasks(sched));
    assert(!aco_sched_has_timer_tasks(sched));
    assert(sched->free_task_n == sched->task_pool_size);

    aco_epoll_free(&sched->io_tasks);
    free(sched->task_pool);
    free(sched);

    aco_gtls_sched = NULL;
}

static 
aco_task_t* aco_sched_get_task(aco_sched_t* sched) {
    if (aco_sched_has_free_tasks(sched)) {
        aco_queue_t* head = aco_queue_front(&sched->free_tasks);
        aco_queue_remove(head);
        sched->free_task_n--;
        return aco_queue_data(head, aco_task_t, queue);
    }
    return NULL;
}

static 
void aco_sched_free_task(aco_sched_t* sched, aco_task_t* task) {
    aco_queue_push_front(&sched->free_tasks, &task->queue);
    sched->free_task_n++;
}

static 
void aco_sched_task(aco_sched_t* sched, aco_task_t* task) {
    assert(!task->blocking && !task->co->is_end);
    aco_queue_push_back(&sched->ready_tasks, &task->queue);
}

static
void aco_sched_task_batch(aco_sched_t* sched, aco_queue_t* tasks) {
    // add the whole queue to tail, except the tasks node
    aco_queue_merge(&sched->ready_tasks, tasks);
    aco_queue_init(tasks);
}

static 
void aco_sched_exit_task(aco_sched_t* sched, aco_task_t* task) {
    assert(!task->blocking && 
           task->attached_fd == -1 && 
           task->co->is_end);

    aco_queue_remove(&task->queue);

    // wake up the waiters
    aco_queue_t* waiters = &task->waiters;
    aco_queue_t* head = aco_queue_front(waiters);
    while(head != waiters) {
        aco_task_t* waiter = aco_queue_data(head, aco_task_t, queue);
        waiter->blocking &= ~ACO_TASK_WAIT_TASK;

        // check other blocking flags 
        if (waiter->blocking != 0) {
            assert(waiter->blocking == ACO_TASK_WAIT_TIME);
            aco_rbtree_delete(&sched->time_tasks, &waiter->timer);
            waiter->blocking = 0;
        }
        waiter->result = ACO_OK;

        head = head->next;
    }
    aco_sched_task_batch(sched, waiters);

    aco_destroy(task->co);
    task->co = NULL;
    aco_sched_free_task(sched, task);
}

aco_tid_t aco_sched_co(aco_sched_t* sched, aco_t* co, char* name) {
    aco_task_t* task = aco_sched_get_task(sched);
    if (task != NULL) {
        aco_task_init(task, co, name);
        aco_sched_task(sched, task);
        aco_log_debug("create task {%s}", task->name);
        return task->tid;
    } else {
        aco_destroy(co);
        aco_log_error("create task {%s} failed, not enough free tasks!!!", name);
        return aco_invalid_tid();
    }
}

static 
aco_task_t* aco_sched_get(aco_sched_t* sched, int index) {
    return &sched->task_pool[index];
}

static 
void aco_sched_timer(aco_sched_t* sched) {
    aco_rbtree_node_t* sentinel = sched->time_tasks.sentinel;

    size_t count = 0;
    size_t block = 0;
    while(1) {
        aco_rbtree_node_t* root = sched->time_tasks.root;
        if (root == sentinel) {
            break;
        }

        aco_rbtree_node_t *node = aco_rbtree_min(&sched->time_tasks);
        if (node->key > sched->current_msec) {
            break;
        }

        aco_task_t* task = (aco_task_t*)((char*)node - offsetof(aco_task_t, timer));
        assert(task->blocking & ACO_TASK_WAIT_TIME);

        aco_rbtree_delete(&sched->time_tasks, &task->timer);
        task->blocking &= ~ACO_TASK_WAIT_TIME;

        // check if the task has other blocking flags
        if (task->blocking) {
            block++;
            aco_log_debug("task {%s} timeout", task->name);
            if (task->blocking == ACO_TASK_WAIT_READ) {
                aco_epoll_del_read(&sched->io_tasks, task->attached_fd);
            } else if (task->blocking == ACO_TASK_WAIT_WRITE) {
                aco_epoll_del_write(&sched->io_tasks, task->attached_fd);
            } else if (task->blocking == ACO_TASK_WAIT_TASK ||
                       task->blocking == ACO_TASK_WAIT_BATON) {
                aco_queue_remove(&task->queue);
            } else {
                assert(0);
            }
            task->blocking = 0;
            task->result = ACO_ETIMEOUT;
        } else {
            task->result = ACO_OK;
        }

        aco_sched_task(sched, task);
        count++;
    }
}

static 
void aco_sched_io_helper(aco_sched_t* sched, aco_task_t* task) {
    if (task->blocking) {
        assert(task->blocking == ACO_TASK_WAIT_TIME);
        aco_rbtree_delete(&sched->time_tasks, &task->timer);
        task->blocking = 0;
    }
    task->result = ACO_OK;
    aco_sched_task(sched, task);
}

static 
void aco_sched_io(aco_sched_t* sched) {

    if (!aco_sched_has_io_tasks(sched)) {
        // if no io task, go back and run ready tasks, 
        // i.e, ready tasks has higher priority
        if (!aco_sched_has_timer_tasks(sched) || 
            aco_sched_has_ready_tasks(sched)) {
            return;
        }
    }

    aco_rbtree_node_t* sentinel = sched->time_tasks.sentinel;
    aco_rbtree_node_t* root = sched->time_tasks.root;

    aco_msec_t wait_msec = -1;

    if (root != sentinel) {
        aco_rbtree_node_t* node = aco_rbtree_min(&sched->time_tasks);
        if (node->key > sched->current_msec) {
            wait_msec = node->key - sched->current_msec;
        } else {
            wait_msec = 0;
        }
    }

    if (aco_sched_has_ready_tasks(sched)) {
        wait_msec = 0;
    }

    aco_log_debug("sched IO wait %ld ms", wait_msec);

    int ret = aco_epoll_wait(&sched->io_tasks, wait_msec);
    assert(ret >= 0);

    for (int i = 0; i < ret; i++) {
        struct epoll_event* ee = &sched->io_tasks.events[i];

        int fd = ee->data.fd;
        int readable = ee->events & EPOLLIN;
        int writable = ee->events & EPOLLOUT;

        aco_task_t* read_task = sched->io_tasks.tasks[fd].read_task;
        aco_task_t* write_task = sched->io_tasks.tasks[fd].write_task;

        // handle EPOLLERR and EPOLLHUP by read or write task
        if ((ee->events & EPOLLERR) || (ee->events & EPOLLHUP)) {
            if (read_task != NULL) {
                readable = 1;
            } else if(write_task != NULL) {
                writable = 1;
            } else {
                assert(0);
            }
        }

        assert(readable || writable);

        if (readable) {
            aco_epoll_del_read(&sched->io_tasks, fd);
            read_task->blocking &= ~ACO_TASK_WAIT_READ;
            aco_sched_io_helper(sched, read_task);
        }
    
        if (writable) {
            aco_epoll_del_write(&sched->io_tasks, fd);
            write_task->blocking &= ~ACO_TASK_WAIT_WRITE;
            aco_sched_io_helper(sched, write_task);
        }
    }
    
    aco_sched_update_time(sched);
    aco_sched_timer(sched);
}

void aco_sched_loop(aco_sched_t* sched) {
    assertptr(aco_gtls_sched);
    assert(aco_gtls_sched == sched);

    aco_queue_t* curr = &sched->ready_tasks;

    size_t iterations = 0;
    size_t total_tasks = 0;

    aco_log_debug("loop started, task pool size: %ld", sched->task_pool_size);

    // loop until all tasks are free
    while(sched->free_task_n != sched->task_pool_size) {
        
        assert(aco_sched_has_ready_tasks(sched) ||
               aco_sched_has_io_tasks(sched) ||
               aco_sched_has_timer_tasks(sched));

        // hit the sentinel node
        if (curr == &sched->ready_tasks) {
            aco_sched_io(sched);
            curr = curr->next;
            iterations++;
            continue;
        }

        aco_task_t* task = aco_queue_data(curr, aco_task_t, queue);
        assert(!task->blocking);

        aco_queue_t* next = curr->next;

        aco_gtls_task = task;
        aco_sys_call_t sys_call = aco_task_run(task);
        aco_gtls_task = NULL;

        if (sys_call != NULL) {
            sys_call(sched, task);
        } else if (task->co->is_end) {
            // this is the only path to exit a task
            aco_log_debug("exit task {%s}", task->name);
            total_tasks++;
            aco_sched_exit_task(sched, task);
        } 
        curr = next;
    }

    aco_log_debug("loop end, iterations: %ld, total tasks: %ld", iterations, total_tasks);
}

///////// system call implementation /////////
static 
void aco_launch_task_impl(aco_sched_t* sched,
                          aco_task_t* task) {
    // restore args
    aco_t* co = aco_gtls_args[0];
    char* name = aco_gtls_args[1];
    
    aco_tid_t tid;
    if(co == NULL || co->is_started || co->main_co == NULL) {
        aco_log_error("create task {%s} failed", name);
        tid = aco_invalid_tid();
    } else {
        tid = aco_sched_co(sched, co, name);
    }
    task->result = tid.tid;
}

static 
void aco_wait_time_helper(aco_sched_t* sched, 
                                 aco_task_t* task,
                                 aco_msec_t timeout) {
    assert (timeout > 0);
    aco_sched_update_time(sched);
    task->timer.key = sched->current_msec + timeout;
    aco_rbtree_insert(&sched->time_tasks, &task->timer);
    task->blocking |= ACO_TASK_WAIT_TIME;
}

static 
void aco_wait_time_impl(aco_sched_t* sched, 
                        aco_task_t* task) {
    aco_msec_t timeout = (aco_msec_t)aco_gtls_args[0];
    if (timeout > 0) {
        aco_queue_remove(&task->queue);
        aco_wait_time_helper(sched, task, timeout);
    } else {
        task->result = ACO_OK;
    }
}

static 
void aco_wait_task_impl(aco_sched_t* sched, 
                               aco_task_t* task) {
    // restore args
    aco_tid_t tid = aco_ptr_to_tid(aco_gtls_args[0]);
    aco_msec_t timeout = (aco_msec_t)aco_gtls_args[1];

    // check index range
    if (tid.index < 0 || 
        tid.index >= sched->task_pool_size || 
        tid.index == task->tid.index) {

        task->result = ACO_EINVALID;
        return;
    } 
    
    aco_task_t* head = aco_sched_get(sched, tid.index);

    // check reuse count
    if (tid.use_count > head->tid.use_count) {
        // invalid reuse count
        task->result = ACO_EINVALID;
    } else if (tid.use_count < head->tid.use_count ||
               aco_task_is_free(head)) {
        // task already exit
        task->result = ACO_OK;
    } else {
        aco_queue_remove(&task->queue);
        aco_queue_push_back(&head->waiters, &task->queue);
        task->blocking |= ACO_TASK_WAIT_TASK;
        if (timeout > 0) {
            aco_wait_time_helper(sched, task, timeout);
        }
        aco_log_debug("task {%s} wait task {%s}", 
                         task->name, head->name);
    }
}

static 
void aco_read_wait_impl(aco_sched_t* sched, 
                               aco_task_t* task) {
    int fd = (int)(int64_t)aco_gtls_args[0];
    aco_msec_t timeout = (aco_msec_t)aco_gtls_args[1];

    aco_epoll_add_read(&sched->io_tasks, fd, task);
    aco_queue_remove(&task->queue);
    task->blocking |= ACO_TASK_WAIT_READ;
    if (timeout > 0) {
        aco_wait_time_helper(sched, task, timeout);
    }
}

static 
void aco_write_wait_impl(aco_sched_t* sched, 
                                aco_task_t* task) {
    int fd = (int)(int64_t)aco_gtls_args[0];
    aco_msec_t timeout = (aco_msec_t)aco_gtls_args[1];

    aco_epoll_add_write(&sched->io_tasks, fd, task);
    aco_queue_remove(&task->queue);
    task->blocking |= ACO_TASK_WAIT_WRITE;
    if (timeout > 0) {
        aco_wait_time_helper(sched, task, timeout);
    }
}

static 
void aco_baton_wait_impl(aco_sched_t* sched, aco_task_t* task) {
    aco_baton_t* baton = aco_gtls_args[0];
    aco_msec_t timeout = (aco_msec_t)aco_gtls_args[1]; 

    if (baton->counter > 0) {
        baton->counter--;
        task->result = ACO_OK;
    } else {
        aco_queue_remove(&task->queue);
        aco_queue_push_back(&baton->waiters, &task->queue);
        task->blocking |= ACO_TASK_WAIT_BATON;
        if (timeout > 0) {
            aco_wait_time_helper(sched, task, timeout);
        }
    }
}

static 
void aco_baton_post_impl(aco_sched_t* sched, aco_task_t* task) {
    aco_baton_t* baton = aco_gtls_args[0];

    if (aco_queue_empty(&baton->waiters)) {
        baton->counter++;
        task->result = ACO_OK;
    } else {
        assert(baton->counter == 0);
        aco_queue_t* q = aco_queue_front(&baton->waiters);
        aco_queue_remove(q);
        aco_task_t* waiter = aco_queue_data(q, aco_task_t, queue);
        
        waiter->blocking &= ~ACO_TASK_WAIT_BATON;
        if (waiter->blocking) {
            assert(waiter->blocking == ACO_TASK_WAIT_TIME);
            aco_rbtree_delete(&sched->time_tasks, &waiter->timer);
            waiter->blocking = 0;
        }
        waiter->result = ACO_OK;
        aco_sched_task(sched, waiter);
    }
}

/////// end


///////////// system call interface //////////////
#define aco_syscall(impl, type) ({ \
    aco_gtls_task->yield_file = strrchr(__FILE__, '/') + 1; \
    aco_gtls_task->yield_func = __FUNCTION__; \
    aco_gtls_task->yield_line = __LINE__; \
    aco_log_debug("yield task {%s}", \
                aco_get_name()); \
    (type)aco_yield(impl);})

aco_tid_t aco_launch_task(aco_cofuncp_t fp, void* arg, aco_share_stack_t* sstk, char* name) {
    int need_unref = 0;
    if (sstk == NULL) {
        sstk = aco_share_stack_new(0);
        need_unref = 1;
    }

    aco_t* co = aco_create(aco_co()->main_co, sstk, 0, fp, arg);
    if (need_unref) {
        aco_share_stack_unref(sstk);
    }

    aco_gtls_args[0] = co;
    aco_gtls_args[1] = name;
    
    void* ret = aco_syscall(aco_launch_task_impl, void*);
    return aco_ptr_to_tid(ret);
}

void aco_sleep(aco_msec_t milliseconds) {
    aco_gtls_args[0] = (void*)milliseconds;
    int64_t ret = aco_syscall(aco_wait_time_impl, int64_t);
    assert(ret == ACO_OK); (void)ret;
}

int64_t aco_wait_task_timeout(aco_tid_t tid, aco_msec_t timeout) {
    aco_gtls_args[0] = aco_tid_to_ptr(tid);
    aco_gtls_args[1] = (void*)timeout;
    return aco_syscall(aco_wait_task_impl, int64_t);
}

int64_t aco_wait_task(aco_tid_t tid) {
    return aco_wait_task_timeout(tid, 0);
}


size_t aco_read_timeout(int fd, void* buf, 
                         size_t count, 
                         aco_msec_t timeout, 
                         int64_t* err) {
    assert(count > 0);

    while (1) {
        ssize_t ret = read(fd, buf, count);
        if (ret > 0) {
            *err = ACO_OK;
            return (size_t)ret;
        } else if (ret == 0) {
            *err = ACO_EOF;
            return 0;
        }
        
        switch (errno) {
        case EWOULDBLOCK:
            aco_gtls_args[0] = (void*)(int64_t)fd;
            aco_gtls_args[1] = (void*)timeout;
            ret = aco_syscall(aco_read_wait_impl, int64_t);
            if (ret != ACO_OK) {
                *err = ret;
                return 0;
            }
            break;
        default:
            *err = errno;
            aco_log_sys("read({%s})", aco_get_name());
            return 0;
        }
    }
    assert(0);
}

size_t aco_read(int fd, void* buf, size_t count, int64_t* err) {
    return aco_read_timeout(fd, buf, count, 0, err);
}

size_t aco_write_timeout(int fd, void* buf, size_t count, aco_msec_t timeout, int64_t* err) {
    assert(count > 0);

    size_t write_n = 0;

    while(1) {

        ssize_t ret = write(fd, (char*)buf + write_n, count - write_n);
        if (ret >= 0) {
            write_n += ret;
            if (write_n == count) {
                *err = ACO_OK;
                return write_n;
            } else {
                continue;
            }
        }

        switch (errno) {
        case EWOULDBLOCK:
            aco_gtls_args[0] = (void*)(int64_t)fd;
            aco_gtls_args[1] = (void*)timeout;
            ret = aco_syscall(aco_write_wait_impl, int64_t);

            if (ret != ACO_OK) {
                *err = ret;
                return write_n;
            }
            break;
        default:
            *err = errno;
            aco_log_sys("write({%s})", aco_get_name());
            return write_n;
        }
    }
    assert(0);
}

size_t aco_write(int fd, void* buf, size_t count, int64_t* err) {
    return aco_write_timeout(fd, buf, count, 0, err);
}

int aco_accept(int fd) {
    while(1) {
        int ret = accept4(fd, NULL, NULL, 
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (ret >= 0) {
            return ret;
        }
        switch (errno)
        {
        case EAGAIN:
        case ENETDOWN:
        case EPROTO:
        case ENOPROTOOPT:
        case EHOSTDOWN:
        case ENONET:
        case EHOSTUNREACH: 
        case EOPNOTSUPP:
        case ENETUNREACH:
        case ECONNABORTED:
        case EINTR:
            aco_gtls_args[0] = (void*)(int64_t)fd;
            aco_gtls_args[1] = (void*)0;
            aco_syscall(aco_read_wait_impl, void);
            break;
        default:
            aco_log_sys("accept4({%s})", aco_get_name());
            return ACO_ESYSTEM;
        }
    }
}

int aco_accept_socket(const char* ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        aco_log_sys("socket({%s})", aco_get_name());
        return ACO_ESYSTEM;
    }

    const int enable = 1;
    int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if (ret < 0) {
        close(fd);
        aco_log_sys("setsockopt({%s})", aco_get_name());
        return ACO_ESYSTEM;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ret = inet_pton(AF_INET, ip, &addr.sin_addr);
    if (ret != 1) {
        close(fd);
        aco_log_sys("inet_pton({%s})", aco_get_name());
        return ACO_ESYSTEM;
    }

    ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        close(fd);
        aco_log_sys("bind({%s})", aco_get_name());
        return ACO_ESYSTEM;
    }

    ret = listen(fd, 1024);
    if (ret < 0) {
        close(fd);
        aco_log_sys("listen({%s})", aco_get_name());
        return ACO_ESYSTEM;
    }

    return fd;
}

static
int aco_connect_once(struct sockaddr_in* addr, aco_msec_t timeout) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        aco_log_sys("socket({%s})", aco_get_name());
        return ACO_ESYSTEM;
    }

    int ret = connect(fd, addr, sizeof(*addr));
    if (ret == 0) {
        return fd;
    }

    switch (errno) {

    case EINPROGRESS:
        aco_gtls_args[0] = (void*)(int64_t)fd;
        aco_gtls_args[1] = (void*)timeout;

        int64_t wail_result = aco_syscall(aco_write_wait_impl, int64_t);
        
        if (wail_result == ACO_ETIMEOUT) {
            aco_log_error("connect({%s}) tiemout", aco_get_name());
            close(fd);
            return ACO_ETIMEOUT;
        }

        assert(wail_result == ACO_OK);

        int optval;
        socklen_t optlen = sizeof(optval);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0) {
            aco_log_sys("getsockopt({%s})", aco_get_name());
            close(fd);
            return ACO_ESYSTEM;
        }
        
        if (optval != 0) {
            aco_log_error("connect({%s}): %s", aco_get_name(), strerror(optval));
            close(fd);
            errno = optval;
            return ACO_ESYSTEM;
        }
        return fd;

    default:
        aco_log_sys("connect({%s})", aco_get_name());
        close(fd);
        return ACO_ESYSTEM;
    }
}

int aco_connect2(struct sockaddr_in* addr, 
                 size_t retry_times, 
                 aco_msec_t timeout) {
    int fd = 0;
    for(size_t i = 0; i < retry_times + 1; i++) {
        if (i > 0 && fd != ACO_ETIMEOUT) {
            aco_sleep(timeout);
        }
        fd = aco_connect_once(addr, timeout);
        if (fd >= 0) {
            return fd;
        }
    }
    return fd;
}

int aco_connect(const char* ip, int port, 
                size_t retry_times, aco_msec_t timeout) {
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htobe16((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        aco_log_sys("inet_pton({%s})", aco_get_name());
        return ACO_ESYSTEM;
    }
    return aco_connect2(&addr, retry_times, timeout);
}

void aco_socket_nodelay(int fd, int on) {
    int optval = on ? 1 : 0;
    int ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                         &optval, sizeof (optval));
    assert(ret == 0);
}

void aco_socket_shutdown(int fd) {
    if (shutdown(fd, SHUT_WR) == -1) {
        aco_log_sys("shutdown({%s})", aco_get_name());
    }
}

void aco_socket_close(int fd) {
    aco_log_info("connection {%s} down", aco_get_name());
    close(fd);
}

int64_t aco_baton_wait_timeout(aco_baton_t* baton, aco_msec_t timeout) {
    assert(baton->counter >= 0);
    if (baton->counter > 0) {
        baton->counter--;
        return 0;
    }
    aco_gtls_args[0] = baton;
    aco_gtls_args[1] = (void*)timeout;
    return aco_syscall(aco_baton_wait_impl, int64_t);
}

void aco_baton_wait(aco_baton_t* baton) {
    int64_t ret = aco_baton_wait_timeout(baton, 0);
    assert(ret == 0); (void)ret;
}

void aco_baton_post(aco_baton_t* baton) {
    assert(baton->counter >= 0);
    if (aco_queue_empty(&baton->waiters)) {
        baton->counter++;
    } else {
        aco_gtls_args[0] = baton;
        aco_syscall(aco_baton_post_impl, void);
    }
}

///////// end

