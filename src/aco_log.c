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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#include "aco_log.h"

aco_log_level_t g_aco_log_level = ACO_LOG_LEVEL_DEBUG;

static const char* log_level_str[] = {
        " [debug]",
        "  [info]",
        " [error]",
};

static void print_time() {

    struct timeval tv;

    gettimeofday(&tv, NULL);
    time_t seconds = tv.tv_sec;

    struct tm tm_time;

    gmtime_r(&seconds, &tm_time);

    fprintf(stderr, "%02d:%02d:%02d.%06ld",
            tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec, tv.tv_usec);
}


void aco_log_base_internal(const char *file,
                           int line,
                           aco_log_level_t level,
                           const char *fmt, ...) {
    va_list ap;

    print_time();
    fprintf(stderr, " %s ", log_level_str[level]);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, " - %s:%d\n", strrchr(file, '/') + 1, line);
}

void aco_log_sys_internal(const char *file,
                          int line,
                          const char *fmt, ...) {
    va_list ap;

    print_time();
    fprintf(stderr, " %s ",  "[syserr]");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, ": %s - %s:%d\n",
            strerror(errno), strrchr(file, '/') + 1, line);
}

