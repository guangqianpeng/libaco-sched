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

#ifndef ACO_RBTREE_H
#define ACO_RBTREE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct aco_rbtree_s       aco_rbtree_t;
typedef struct aco_rbtree_node_s  aco_rbtree_node_t;
typedef int64_t                   aco_rbtree_key_t;

struct aco_rbtree_s {
    aco_rbtree_node_t*  root;
    aco_rbtree_node_t*  sentinel;
    size_t              size;
};

struct aco_rbtree_node_s {
    aco_rbtree_key_t    key;
    aco_rbtree_node_t*  left;
    aco_rbtree_node_t*  right;
    aco_rbtree_node_t*  parent;
    char                color;
};

void aco_rbtree_init(aco_rbtree_t* tree, aco_rbtree_node_t* sentinel);
int aco_rbtree_empty(aco_rbtree_t* tree);
void aco_rbtree_insert(aco_rbtree_t* tree, aco_rbtree_node_t* node);
void aco_rbtree_delete(aco_rbtree_t* tree, aco_rbtree_node_t* node);
aco_rbtree_node_t* aco_rbtree_min(aco_rbtree_t* tree);

#ifdef __cplusplus
}
#endif

#endif

