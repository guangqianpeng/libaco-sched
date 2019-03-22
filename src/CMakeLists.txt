add_library(aco STATIC 
    acosw.S 
    aco_rbtree.c 
    aco_stream.c 
    aco_time_wheel.c
    aco.c 
    aco_log.c
    aco_scheduler.c 
    )

set(ACO_HEADERS 
    aco.h 
    aco_scheduler.h 
    aco_stream.h 
    aco_log.h 
    aco_time_wheel.h
    aco_rbtree.h
    aco_queue.h
    )
    
install(FILES ${ACO_HEADERS} DESTINATION include/aco)
install(TARGETS aco DESTINATION lib)