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

#include <endian.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#include "aco_stream.h"
#include "aco_log.h"
#include "aco_scheduler.h"
#include "aco_assert_override.h"

static 
void aco_stream_debug(aco_stream_t* s) {

    const char* result = NULL;
    switch (s->result) {
    case ACO_OK:
        result = "Ok";
        break;
    case ACO_EINVALID:
        result = "Invalid argument";
        break;
    case ACO_ESYSTEM:
        result = "System error";
        break;
    case ACO_ETIMEOUT:
        result = "Timeout";
        break;
    case ACO_EOF:
        result = "EOF";
        break;
    default:
        result = "Unknown error";
        break; 
    }

    aco_log_debug( 
           "stream {%s} aco: {%s}, sys: {%s}, send: %lu B buf: %lu B, recv: %lu B buf: %lu B", 
           aco_get_name(),
           result, strerror(s->saved_errno), 
           s->write_n, s->out.last,
           s->read_n, s->in.last - s->in.curr);
}

aco_stream_t* aco_stream_create(int fd, 
                        size_t in_size,
                        size_t out_size,
                        aco_msec_t timeout) {

    aco_stream_t* s = malloc(sizeof(aco_stream_t));
    assertalloc_ptr(s);

    s->fd = fd;
    s->timeout = timeout;
    s->saved_errno = ACO_OK;
    s->read_n = 0;
    s->write_n = 0;

    if (in_size < 8) {
        in_size = 8;
    }
    s->in.buf = malloc(in_size);
    assertalloc_ptr(s->in.buf);
    s->in.size = in_size;
    s->in.curr = 0;
    s->in.last = 0;

    if (out_size < 8) {
        out_size = 8;
    }
    s->out.buf = malloc(out_size);
    assertalloc_ptr(s->out.buf);
    s->out.size = out_size;
    s->out.last = 0;

    return s;
}


void aco_stream_destroy(aco_stream_t* s) {
    if (s->out.last > 0) {
        aco_stream_flush(s);
    }
    aco_stream_debug(s);
    aco_socket_close(s->fd);
    free(s->in.buf);
    free(s->out.buf);
    free(s);
}

static
void aco_stream_save_errno(aco_stream_t* s, int64_t err) {
    if (s->saved_errno == ACO_OK) {
        s->saved_errno = err;
    }
}

static
size_t aco_stream_write_fd_helper(aco_stream_t* s, void* buf, size_t count) {

    size_t write_n = aco_write_timeout(s->fd, buf, count, s->timeout, &s->result);

    if (s->result > 0) {
        aco_stream_save_errno(s, s->result);
        s->result = ACO_ESYSTEM;
        return write_n;
    } 
    
    if (s->result == ACO_ETIMEOUT) {
        return write_n;
    }

    assert(s->result == ACO_OK && write_n == count);
    
    s->write_n += write_n;

    return write_n;
}

size_t aco_stream_flush(aco_stream_t* s) {
    if (s->out.last > 0) {
        size_t count = aco_stream_write_fd_helper(
                                    s, 
                                    s->out.buf, 
                                    s->out.last);
    
        // partial write is ok
        if (count > 0) {
            s->out.last -= count;
            if (s->out.last > 0) {
                memmove(s->out.buf, s->out.buf + count, s->out.last);
            }
        }
        return count;
    }
    s->result = ACO_OK;
    return 0;
}

void aco_stream_shutdown(aco_stream_t* s) {
    if (s->out.last > 0) {
        aco_stream_flush(s);
    }
    aco_socket_shutdown(s->fd);
}

void aco_stream_close(aco_stream_t* s) {
    if (s->out.last > 0) {
        aco_stream_flush(s);
    }
    // DO NOT close the fd, leave it to destroy
    shutdown(s->fd, SHUT_RDWR);
}

#define FLUSH(s) do { \
    aco_stream_flush(s); \
    if (s->result != ACO_OK) { \
        return 0; \
    } \
} while (0)

size_t aco_stream_write_n(aco_stream_t* s, void* buf, size_t count) {
    FLUSH(s);
    return aco_stream_write_fd_helper(s, buf, count);
}

size_t aco_stream_write_8(aco_stream_t* s, char ch) {
    if (s->out.size <= s->out.last) {
        FLUSH(s);
    }
    assert(s->out.size > s->out.last);
    s->out.buf[s->out.last] = ch;
    s->out.last++;
    s->result = ACO_OK;
    return 1;
}

size_t aco_stream_write_16(aco_stream_t* s, uint16_t u16) {
    if (s->out.size - s->out.last < 2) {
        FLUSH(s);
    }
    assert(s->out.size - s->out.last >= 2);
    u16 = htobe16(u16);
    memcpy(s->out.buf + s->out.last, &u16, 2);
    s->out.last += 2;
    s->result = ACO_OK;
    return 2;
}


size_t aco_stream_write_32(aco_stream_t* s, uint32_t u32) {
    if (s->out.size - s->out.last < 4) {
        FLUSH(s);
    }
    assert(s->out.size - s->out.last >= 4);
    u32 = htobe32(u32);
    memcpy(s->out.buf + s->out.last, &u32, 4);
    s->out.last += 4;
    s->result = ACO_OK;
    return 4;
}

size_t aco_stream_write_64(aco_stream_t* s, uint64_t u64) {
    if (s->out.size - s->out.last < 8) {
        FLUSH(s);
    }
    assert(s->out.size - s->out.last >= 8);
    u64 = htobe64(u64);
    memcpy(s->out.buf + s->out.last, &u64, 8);
    s->out.last += 8;
    s->result = ACO_OK;
    return 8;
}

static 
size_t aco_stream_read_fd_helper(aco_stream_t* s, void* buf, size_t count) {
    
    assert(count > 0);

    size_t read_n = aco_read_timeout(s->fd, buf, count, s->timeout, &s->result);

    if (s->result > 0) {
        aco_stream_save_errno(s, s->result);
        s->result = ACO_ESYSTEM;
        return read_n;
    }

    if (s->result == ACO_ETIMEOUT) {
        return read_n;
    }

    
    assert(s->result == ACO_OK || s->result == ACO_EOF);

    s->read_n += read_n;

    return read_n;
}

static
size_t aco_stream_read_fd(aco_stream_t* s) {
    s->in.last -= s->in.curr;
    if (s->in.last > 0) {
        memmove(s->in.buf, s->in.buf + s->in.curr, s->in.last);
    }
    s->in.curr = 0;

    size_t read_n = aco_stream_read_fd_helper(
                             s, 
                             s->in.buf + s->in.last,
                             s->in.size - s->in.last);
    s->in.last += read_n;
    return read_n;
}

size_t aco_stream_read_n(aco_stream_t* s, void* buf, size_t count) {
    size_t remain = s->in.last - s->in.curr;
    if (remain == 0) {
        return aco_stream_read_fd_helper(s, buf, count);
    } 
    memcpy(buf, s->in.buf + s->in.curr, remain);
    s->in.curr = 0;
    s->in.last = 0;
    s->result = ACO_OK;
    return remain;
}

size_t aco_stream_read_8(aco_stream_t* s, char* ch) {
    if (s->in.curr >= s->in.last) {
        size_t count = aco_stream_read_fd(s);
        if (s->result != ACO_OK) {
            return count;
        }
    }
    *ch = s->in.buf[s->in.curr];
    s->in.curr++;
    s->result = ACO_OK;
    return 1;
}

size_t aco_stream_read_16(aco_stream_t* s, uint16_t* u16) {
    while (s->in.last - s->in.curr < 2) {
        size_t count = aco_stream_read_fd(s);
        if (s->result != ACO_OK) {
            return count;
        }
    }
    memcpy(u16, s->in.buf + s->in.curr, 2);
    *u16 = be16toh(*u16);
    s->in.curr += 2;
    s->result = ACO_OK;
    return 2;
}

size_t aco_stream_read_32(aco_stream_t* s, uint32_t* u32) {
    while (s->in.last - s->in.curr < 4) {
        size_t count = aco_stream_read_fd(s);
        if (s->result != ACO_OK) {
            return count;
        }
    }
    memcpy(u32, s->in.buf + s->in.curr, 4);
    *u32 = be32toh(*u32);
    s->in.curr += 4;
    s->result = ACO_OK;
    return 4;
}

size_t aco_stream_read_64(aco_stream_t* s, uint64_t* u64) {
    while (s->in.last - s->in.curr < 8) {
        size_t count = aco_stream_read_fd(s);
        if (s->result != ACO_OK) {
            return count;
        }
    }
    memcpy(u64, s->in.buf + s->in.curr, 8);
    *u64 = be64toh(*u64);
    s->in.curr += 8;
    s->result = ACO_OK;
    return 8;
}

