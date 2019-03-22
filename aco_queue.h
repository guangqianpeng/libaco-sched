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


#ifndef ACO_QUEUE_H
#define ACO_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct aco_queue_s aco_queue_t;

struct aco_queue_s {
    aco_queue_t  *prev;
    aco_queue_t  *next;
};

#define aco_queue_init(q) \
    (q)->prev = q;        \
    (q)->next = q

#define aco_queue_empty(q) \
    (q == (q)->prev)

#define aco_queue_push_front(q, x)  \
    (x)->next = (q)->next;          \
    (x)->next->prev = x;            \
    (x)->prev = q;                  \
    (q)->next = x

#define aco_queue_push_back(q, x)   \
    (x)->prev = (q)->prev;          \
    (x)->prev->next = x;            \
    (x)->next = q;                  \
    (q)->prev = x

#define aco_queue_front(q) (q)->next

#define aco_queue_remove(x)      \
    (x)->next->prev = (x)->prev; \
    (x)->prev->next = (x)->next

#define aco_queue_merge(q, n)     \
    (q)->prev->next = (n)->next;  \
    (n)->next->prev = (q)->prev;  \
    (q)->prev = (n)->prev;        \
    (q)->prev->next = q;

#define aco_queue_data(q, type, link) \
    (type*)((char*)q - offsetof(type, link))

#ifdef __cplusplus
}
#endif

#endif

