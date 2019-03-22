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

#ifndef ACO_TIME_WHEEL_H
#define ACO_TIME_WHEEL_H

#include <stddef.h>

#include "aco_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

// the handler shuuld never yield!!!
typedef void(*aco_time_wheel_handler_t)(aco_queue_t* waiter);

typedef aco_queue_t aco_bucket_t;

typedef struct {
    aco_time_wheel_handler_t handler;
    size_t                   total;  // total items in wheel
    size_t                   tail;   // current bucket
    size_t                   size;   // number of bucket
    aco_bucket_t             buckets[];
} aco_time_wheel_t;

aco_time_wheel_t* aco_time_wheel_create(size_t size, aco_time_wheel_handler_t handler);
void aco_time_wheel_destroy(aco_time_wheel_t* w);

size_t aco_time_wheel_run(aco_time_wheel_t* w);

void aco_time_wheel_insert(aco_time_wheel_t* w, aco_queue_t* waiter);
void aco_time_wheel_refresh(aco_time_wheel_t* w, aco_queue_t* waiter);
void aco_time_wheel_remove(aco_time_wheel_t* w, aco_queue_t* waiter);

#define aco_time_wheel_refresh_if_waiting(w, waiter) do {\
    if (!aco_queue_empty(waiter)) \
        aco_time_wheel_refresh((w), (waiter)); \
} while(0)

#define aco_time_wheel_remove_if_waiting(w, waiter) do {\
    if (!aco_queue_empty(waiter)) \
        aco_time_wheel_remove((w), (waiter)); \
} while(0)

#define aco_time_wheel_waiting(waiter) \
    (!aco_queue_empty(waiter))

#ifdef __cplusplus
}
#endif


#endif

