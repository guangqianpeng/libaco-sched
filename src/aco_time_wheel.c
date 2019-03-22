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

#include <stdlib.h>

#include "aco_time_wheel.h"
#include "aco_assert_override.h"


aco_time_wheel_t* aco_time_wheel_create(size_t size, aco_time_wheel_handler_t handler) {
    assert(size > 0);

    aco_time_wheel_t* w = malloc(sizeof(aco_time_wheel_t) + size * sizeof(aco_bucket_t));
    assertalloc_ptr(w);

    for (size_t i = 0; i < size; i++) {
        aco_bucket_t* bucket = &w->buckets[i];
        aco_queue_init(bucket);
    }

    w->handler = handler;
    w->total = 0;
    w->tail = 0;
    w->size = size;

    return w;
}

void aco_time_wheel_destroy(aco_time_wheel_t* w) {
    free(w);
}

size_t aco_time_wheel_run(aco_time_wheel_t* w) {
    w->tail++;
    if (w->tail >= w->size) {
        w->tail -= w->size;
    }

    aco_queue_t* bucket = &w->buckets[w->tail];
    aco_queue_t* waiter = aco_queue_front(bucket);
    
    size_t count = 0;
    while (waiter != bucket) {
        aco_queue_t* next = waiter->next;

        // ensure aco_time_wheel_waiting() return false
        aco_queue_init(waiter);
        w->handler(waiter);

        waiter = next;
        count++;
    }
    assert(w->total >= count);
    w->total -= count;
    aco_queue_init(bucket);
    return count;
}

void aco_time_wheel_insert(aco_time_wheel_t* w, aco_queue_t* waiter) {
    assert(aco_queue_empty(waiter));
    aco_queue_push_back(&w->buckets[w->tail], waiter);
    w->total++;
}

void aco_time_wheel_refresh(aco_time_wheel_t* w, aco_queue_t* waiter) {
    assert(!aco_queue_empty(waiter));
    aco_queue_remove(waiter);
    aco_queue_push_back(&w->buckets[w->tail], waiter);
}

void aco_time_wheel_remove(aco_time_wheel_t* w, aco_queue_t* waiter) {
    assert(!aco_queue_empty(waiter));
    aco_queue_remove(waiter);
    w->total--;
}

