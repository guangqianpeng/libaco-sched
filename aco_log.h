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

#ifndef ACO_LOG_H
#define ACO_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ACO_LOG_LEVEL_DEBUG,
    ACO_LOG_LEVEL_INFO,
    ACO_LOG_LEVEL_ERROR,
} aco_log_level_t;

extern aco_log_level_t g_aco_log_level;

void aco_log_base_internal(const char *file,
                           int line,
                           aco_log_level_t level,
                           const char *fmt, ...);
void aco_log_sys_internal(const char *file,
                          int line,
                          const char *fmt, ...);

#define aco_log_base(level, fmt, ...) \
    aco_log_base_internal(__FILE__, __LINE__, level, fmt, ##__VA_ARGS__)

#define aco_log_sys(fmt, ...) \
    aco_log_sys_internal(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define aco_log_debug(fmt, ...) do {\
    if(g_aco_log_level <= ACO_LOG_LEVEL_DEBUG) \
        aco_log_base(ACO_LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__);\
} while(0)

#define aco_log_info(fmt, ...) do {\
    if(g_aco_log_level <= ACO_LOG_LEVEL_INFO) \
        aco_log_base(ACO_LOG_LEVEL_INFO, fmt, ##__VA_ARGS__);\
} while(0)

#define aco_log_error(fmt, ...)    aco_log_base(ACO_LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define aco_log_syserr(fmt, ...)   aco_log_sys(fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif

