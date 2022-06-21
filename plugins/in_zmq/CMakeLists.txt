if (FLB_IN_ZMQ)
  find_package(PkgConfig REQUIRED)
endif (FLB_IN_ZMQ)

set(src
  in_zmq.c)

FLB_PLUGIN(in_zmq "${src}" "${CZMQ_LIBRARIES}")
target_link_libraries(flb-plugin-in_zmq -lczmq)
