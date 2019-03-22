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

#ifndef ACO_STREAM_H
#define ACO_STREAM_H

#include "aco_scheduler.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int           fd;

    int64_t       result;
    int           saved_errno; // errno of system call

    aco_msec_t    timeout;

    size_t         read_n;
    size_t         write_n;

    struct {
        char*      buf;
        size_t     size;
        size_t     curr;
        size_t     last;
    } in;
    struct {
        char*      buf;
        size_t     size;
        size_t     last;
    } out;
} aco_stream_t;


aco_stream_t* aco_stream_create(int fd, 
                        size_t in_size,
                        size_t out_size,
                        aco_msec_t timeout);
void aco_stream_destroy(aco_stream_t* s);

void aco_stream_shutdown(aco_stream_t* s);
void aco_stream_close(aco_stream_t* s);

size_t aco_stream_flush(aco_stream_t* s);

size_t aco_stream_write_n(aco_stream_t* s, void* buf, size_t count);
size_t aco_stream_write_8(aco_stream_t* s, char ch);
size_t aco_stream_write_16(aco_stream_t* s, uint16_t u16);
size_t aco_stream_write_32(aco_stream_t* s, uint32_t u32);
size_t aco_stream_write_64(aco_stream_t* s, uint64_t u64);

size_t aco_stream_read_n(aco_stream_t* s, void* buf, size_t count);
size_t aco_stream_read_8(aco_stream_t* s, char* ch);
size_t aco_stream_read_16(aco_stream_t* s, uint16_t* u16);
size_t aco_stream_read_32(aco_stream_t* s, uint32_t* u32);
size_t aco_stream_read_64(aco_stream_t* s, uint64_t* u64);

#define aco_stream_set_timeout(s, t) (s)->timeout = (t)

#ifdef __cplusplus
}
#endif


#endif

