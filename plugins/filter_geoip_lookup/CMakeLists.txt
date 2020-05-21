#add_subdirectory(libmaxminddb-1.4.2 EXCLUDE_FROM_ALL)
#
## libmaxminddb headers
#include_directories(libmaxminddb-1.4.2/src/)

set(src
  filter_geoip_lookup.c)

FLB_PLUGIN(filter_geoip_lookup "${src}" "")

target_link_libraries(flb-plugin-filter_geoip_lookup -lmaxminddb)
