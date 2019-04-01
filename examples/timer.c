#include "app_template.h"

void timer() {
    while (1) {
        aco_sleep(1000);
        aco_log_info("%s wakeup", aco_get_name());
    }
}

void start() {
    aco_launch_task(timer, NULL, NULL, "timer 1");
    aco_launch_task(timer, NULL, NULL, "timer 2");
    aco_exit();
}

int main() {
    app_config_t config;
    aco_config_init(&config);

    config.type = APP_OTHER;
    config.task_pool_size = 3;
    config.name = "timer";
    config.main_func = start;
    config.log_level = ACO_LOG_LEVEL_INFO;

    app_template_run(&config);   
}
