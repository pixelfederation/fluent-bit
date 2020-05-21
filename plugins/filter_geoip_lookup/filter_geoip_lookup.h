/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_FILTER_GEOIP_LOOKUP_H
#define FLB_FILTER_GEOIP_LOOKUP_H

struct lookup_data {
    char *country_code;
    bool country_code_found;
    double latitude;
    bool latitude_found;
    double longitude;
    bool longitude_found;
};

struct geoip_lookup_ctx {
    int include_map_size;
    struct flb_filter_instance *ins;
    char *input_field;
    char *output_field;
    char *db_path;
    struct MMDB_S *mmdb;
    bool include_country_code;
    bool include_location;
};


#endif
