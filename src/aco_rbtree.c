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

#include <stddef.h>

#include "aco_rbtree.h"

#define RED     0
#define BLACK   1

static void rotate_left(aco_rbtree_t* tree, aco_rbtree_node_t* node);
static void rotate_right(aco_rbtree_t* tree, aco_rbtree_node_t* node);

static void insert(aco_rbtree_t* tree, aco_rbtree_node_t* node);
static void transplant(aco_rbtree_t* tree, aco_rbtree_node_t* p, aco_rbtree_node_t* c); /* remove p, imporve c */
static void delete_fix(aco_rbtree_t* tree, aco_rbtree_node_t* node);

static aco_rbtree_node_t* min(aco_rbtree_node_t* node, aco_rbtree_node_t* sentinel);

#define is_red(node)    ((node)->color == RED)
#define is_black(node)  ((node)->color == BLACK)
#define set_red(node)   ((node)->color = RED)
#define set_black(node) ((node)->color = BLACK)

void aco_rbtree_init(aco_rbtree_t* tree, aco_rbtree_node_t* sentinel) {
    aco_rbtree_node_t* root;

    root = tree->root = sentinel;
    tree->sentinel = sentinel;
    tree->size = 0;

    set_black(root);

    root->left = NULL;
    root->right = NULL;

    /* this field is useful when deleting */
    root->parent = NULL;
}

int aco_rbtree_empty(aco_rbtree_t* tree) {
    return tree->root == tree->sentinel;
}

void aco_rbtree_insert(aco_rbtree_t* tree, aco_rbtree_node_t* node) {
    aco_rbtree_node_t *temp;
    
    tree->size++;

    /* empty tree */
    if (tree->root == tree->sentinel) {
        set_black(node);
        node->left = tree->sentinel;
        node->right = tree->sentinel;
        node->parent = tree->sentinel;
        tree->root = node;
        return;
    }

    insert(tree, node);

    /* since is_black(sentinel) && root.parent==sentinel,
     * node==root can break the loop */
    while (is_red(node->parent)) {
        if (node->parent == node->parent->parent->left) {
            temp = node->parent->parent->right;
            if (is_red(temp)) {
                set_black(node->parent);
                set_black(temp);
                set_red(temp->parent);
                node = node->parent->parent;
            }
            else {
                if (node->parent->right == node) {
                    rotate_left(tree, node->parent);
                    node = node->left;
                }

                set_black(node->parent);
                set_red(node->parent->parent);
                rotate_right(tree, node->parent->parent);
                break;  /* now is_black(node.parent), we break */
            }
        }
        else {
            temp = node->parent->parent->left;
            if (is_red(temp)) {
                set_black(node->parent);
                set_black(temp);
                set_red(temp->parent);
                node = node->parent->parent;
            }
            else {
                if (node->parent->left == node) {
                    rotate_right(tree, node->parent);
                    node = node->right;
                }

                set_black(node->parent);
                set_red(node->parent->parent);
                rotate_left(tree, node->parent->parent);
                break;
            }
        }
    }

    set_black(tree->root);
}

void aco_rbtree_delete(aco_rbtree_t* tree, aco_rbtree_node_t* node) {

    /* subt is the node that needs to be moved, temp is a subtree of subt
     * color==subt.color
     * */
    aco_rbtree_node_t* sentinel, *temp, *subt;
    char      color;

    tree->size--;

    sentinel = tree->sentinel;
    subt = node;
    color = subt->color;

    /* delete */
    if (node->left == sentinel) {
        temp = subt->right;
        transplant(tree, subt, temp);
    }
    else if (node->right == sentinel) {
        temp = subt->left;
        transplant(tree, subt, temp);
    }
    else {
        subt = min(node->right, tree->sentinel);
        color = subt->color;
        temp = subt->right;

        if (subt->parent != node) {
            transplant(tree, subt, temp);
            subt->right = node->right;
            subt->right->parent = subt;
        }
        else {
            temp->parent = subt;
        }

        transplant(tree, node, subt);
        subt->left = node->left;
        subt->left->parent = subt;
        subt->color = node->color;
    }

    if (color == BLACK) {
        delete_fix(tree, temp);
    }
}

aco_rbtree_node_t* aco_rbtree_min(aco_rbtree_t* tree)
{
    return min(tree->root, tree->sentinel);
}

static void rotate_left(aco_rbtree_t* tree, aco_rbtree_node_t* node) {
    aco_rbtree_node_t *temp;

    temp = node->right;

    node->right = temp->left;

    if (node->right != tree->sentinel) {
        node->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == tree->root) {
        tree->root = temp;
    }
    else if (node == node->parent->left) {
        node->parent->left = temp;
    }
    else {
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}

static void rotate_right(aco_rbtree_t* tree, aco_rbtree_node_t* node) {
    aco_rbtree_node_t* temp;

    temp = node->left;

    node->left = temp->right;
    if (node->left != tree->sentinel) {
        node->left->parent = node;
    }

    temp->parent = node->parent;

    if (tree->root == node) {
        tree->root = temp;
    }
    else if (node == node->parent->left) {
        node->parent->left = temp;
    }
    else {
        node->parent->right = temp;
    }

    temp->right = node;
    node->parent = temp;
}

static void insert(aco_rbtree_t* tree, aco_rbtree_node_t* node) {

    aco_rbtree_node_t* *p,* temp;

    temp = tree->root;
    while (1) {
        if (node->key < temp->key) {
            p = &temp->left;
        }
        else {
            p = &temp->right;
        }

        if (*p == tree->sentinel)
            break;

        temp =* p;
    }

    set_red(node);
    node->left = tree->sentinel;
    node->right = tree->sentinel;
    node->parent = temp;
   * p = node;
}

static void transplant(aco_rbtree_t* tree, aco_rbtree_node_t* p, aco_rbtree_node_t* c) {
    if (p == tree->root) {
        tree->root = c;
    }
    else if (p == p->parent->left) {
        p->parent->left = c;
    }
    else {
        p->parent->right = c;
    }
    c->parent = p->parent;
}

static void delete_fix(aco_rbtree_t* tree, aco_rbtree_node_t* node) {
    aco_rbtree_node_t* brother;

    while (node != tree->root && is_black(node)) {
        if (node == node->parent->left) {
            brother = node->parent->right;

            if (is_red(brother)) {
                set_red(brother->parent);
                set_black(brother);
                rotate_left(tree, brother->parent);
                brother = node->parent->right;
            }

            if (is_black(brother->left) && is_black(brother->right)) {
                set_red(brother);
                node = node->parent;
            }
            else {
                if (is_black(brother->right)) {
                    set_red(brother);
                    set_black(brother->left);
                    rotate_right(tree, brother);
                    brother = node->parent->right;
                }

                brother->color = brother->parent->color;
                set_black(brother->parent);
                set_black(brother->right);
                rotate_left(tree, brother->parent);
                break;
            }
        }
        else {
            brother = node->parent->left;

            if (is_red(brother)) {
                set_black(brother);
                set_red(brother->parent);
                rotate_right(tree, brother->parent);
                brother = node->parent->left;
            }

            if (is_black(brother->left) && is_black(brother->right)) {
                set_red(brother);
                node = node->parent;
            }
            else {
                if (is_black(brother->left)) {
                    set_red(brother);
                    set_black(brother->right);
                    rotate_left(tree, brother);
                    brother = node->parent->left;
                }

                brother->color = brother->parent->color;
                set_black(brother->parent);
                set_black(brother->left);
                rotate_right(tree, brother->parent);
                break;
            }
        }
    }
    set_black(node);
}

static aco_rbtree_node_t* min(aco_rbtree_node_t* node, aco_rbtree_node_t* sentinel) {
    while (node->left != sentinel) {
        node = node->left;
    }
    return node;
}

