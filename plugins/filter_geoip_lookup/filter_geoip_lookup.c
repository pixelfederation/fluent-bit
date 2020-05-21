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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time.h>

#include <maxminddb.h>
#include <msgpack.h>

#include "filter_geoip_lookup.h"


#define PLUGIN_NAME "filter_geoip_lookup"


static int parse_boolean_value(const char *pval) {
    if (pval) {
        if (strcasecmp(pval, "true") == 0 || strcasecmp(pval, "on") == 0) {
            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}


static int cb_geoip_init(struct flb_filter_instance *f_ins,
                         struct flb_config *config,
                         void *data) {
    struct geoip_lookup_ctx *ctx = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct geoip_lookup_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->include_map_size = 0;
    ctx->ins = f_ins;
    ctx->input_field = flb_filter_get_property("input_field", f_ins);
    ctx->output_field = flb_filter_get_property("output_field", f_ins);
    ctx->db_path = flb_filter_get_property("db_path", f_ins);
    ctx->include_country_code = parse_boolean_value(flb_filter_get_property("include_country_code", f_ins));
    if (ctx->include_country_code != FLB_FALSE) {
        ctx->include_map_size++;
    }
    ctx->include_location = parse_boolean_value(flb_filter_get_property("include_location", f_ins));
    if (ctx->include_location != FLB_FALSE) {
        ctx->include_map_size++;
    }
    if (!ctx->include_map_size) {
        flb_plg_error(ctx->ins, "There has to be at least one geoip field to lookup.");
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    ctx->mmdb = flb_malloc(sizeof(struct MMDB_s));
    int status = MMDB_open(ctx->db_path, MMDB_MODE_MMAP, ctx->mmdb);
    if (MMDB_SUCCESS != status) {
        flb_plg_error(ctx->ins, "could not load geoip DB '%s'",
                      ctx->db_path);
        return -1;
    }

    return 0;
}


static int
find_country_code(const MMDB_lookup_result_s res, const MMDB_entry_data_s entry_data, struct lookup_data *ld) {
    int status;
    status = MMDB_get_value(&res.entry, &entry_data, "country", "iso_code", NULL);

    if (MMDB_SUCCESS == status) {
        if (entry_data.has_data) {
            if (entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                ld->country_code = flb_strndup(entry_data.utf8_string, entry_data.data_size);
                ld->country_code_found = true;
                return 0;
            }
        }
    }
    ld->country_code_found = false;
    return -1;
}

static int find_latitude(const MMDB_lookup_result_s res, const MMDB_entry_data_s entry_data, struct lookup_data *ld) {
    int status;
    status = MMDB_get_value(&res.entry, &entry_data, "location", "latitude", NULL);

    if (MMDB_SUCCESS == status) {
        if (entry_data.has_data) {
            if (entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                ld->latitude = entry_data.double_value;
                ld->latitude_found = true;
                return 0;
            }
        }
    }
    ld->latitude_found = false;
    return -1;
}

static int
find_longitude(const MMDB_lookup_result_s res, const MMDB_entry_data_s entry_data, struct lookup_data *ld) {
    int status;
    status = MMDB_get_value(&res.entry, &entry_data, "location", "longitude", NULL);

    if (MMDB_SUCCESS == status) {
        if (entry_data.has_data) {
            if (entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                ld->longitude = entry_data.double_value;
                ld->longitude_found = true;
                return 0;
            }
        }
    }
    ld->longitude_found = false;
    return -1;
}

static int cb_geoip_filter(const void *data, size_t bytes,
                           const char *tag, int tag_len,
                           void **out_buf, size_t *out_size,
                           struct flb_filter_instance *f_ins,
                           void *context,
                           struct flb_config *config) {
    struct geoip_lookup_ctx *ctx = context;
    (void) f_ins;
    (void) config;
    size_t off = 0;
    int i = 0;
    struct flb_time tm;
    int total_records;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object *obj;
    msgpack_object_kv *kv;
    char *ip_string;

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    /* Iterate over each item */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)
           == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map. We 'unpack' each record, and then re-pack
         * it with the new fields added.
         */
        struct lookup_data *ld = NULL;
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* obj should now be the record map */
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* iterate through record map and ip string */
        kv = obj->via.map.ptr;
        for (i = 0; i < obj->via.map.size; i++) {
            /* if its not string we can go next */
            if ((kv + i)->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }
            /* if size doesnt match, we can go next */
            if ((kv + i)->key.via.str.size != flb_sds_len(ctx->input_field)) {
                continue;
            }
            /* if string doesnt match go next */
            if (strncmp((kv + i)->key.via.str.ptr, ctx->input_field,
                        flb_sds_len(ctx->input_field)) != 0) {
                continue;
            }
            /* if value is not string go next*/
            if ((kv + i)->val.type != MSGPACK_OBJECT_STR) {
                continue;
            }
            /* if value too long go next */
            if ((kv + i)->val.via.str.size >= 128) {
                continue;
            }
            ip_string = flb_strndup((kv + i)->val.via.str.ptr, (kv + i)->val.via.str.size);
            break;
        }

        /**
         * find country
         */
        MMDB_entry_data_s entry_data;
        MMDB_lookup_result_s res;
        int gai_error, mmdb_error;
        res = MMDB_lookup_string(ctx->mmdb, ip_string, &gai_error, &mmdb_error);
        if (0 != gai_error) {
            flb_plg_error(ctx->ins, "Error from getaddrinfo for %s - %s\n", ip_string, gai_strerror(gai_error));

            flb_free(ip_string);
            return FLB_FILTER_NOTOUCH;
        }

        if (MMDB_SUCCESS != mmdb_error) {
            flb_plg_error(ctx->ins, "Got an error from libmaxminddb: %s\n", MMDB_strerror(mmdb_error));

            flb_free(ip_string);
            return FLB_FILTER_NOTOUCH;
        }

        if (res.found_entry) {


            /* Create lookup struct */
            ld = flb_malloc(sizeof(struct lookup_data));
            if (!ld) {
                flb_errno();
                return -1;
            }

            if (ctx->include_country_code) {
                // find country
                find_country_code(res, entry_data, ld);
            }
            if (ctx->include_location) {
//            find_location()
                find_longitude(res, entry_data, ld);
                find_latitude(res, entry_data, ld);
            }
        } else {
            flb_free(ip_string);
            return FLB_FILTER_NOTOUCH;
        }


        /* re-pack the array into a new buffer */
        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        /* new record map size is old size + the new keys we will add */
        total_records = obj->via.map.size;
        msgpack_pack_map(&tmp_pck, total_records + 1);

        /* iterate through the old record map and add it to the new buffer */
        kv = obj->via.map.ptr;
        for (i = 0; i < obj->via.map.size; i++) {
            msgpack_pack_object(&tmp_pck, (kv + i)->key);
            msgpack_pack_object(&tmp_pck, (kv + i)->val);
        }

        /* append new keys */

        if (true) { // todo: mozno iterovat cez fieldy ktore maju byt includenute
            /* append lookup object with name from config */
            msgpack_pack_str(&tmp_pck, strlen(ctx->output_field));
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->output_field,
                                  strlen(ctx->output_field));


            /* Create the nest map value */
            msgpack_pack_map(&tmp_pck, ctx->include_map_size);

            /* Pack the nested items */
            if (ctx->include_location) {
                //pack longitude
                msgpack_pack_str(&tmp_pck, strlen("location"));
                msgpack_pack_str_body(&tmp_pck,
                                      "location",
                                      strlen("location"));
                msgpack_pack_map(&tmp_pck, 2);
                msgpack_pack_str(&tmp_pck, strlen("lon"));
                msgpack_pack_str_body(&tmp_pck,
                                      "lon",
                                      strlen("lon"));
                if (ld->longitude_found) {
                    msgpack_pack_double(&tmp_pck, ld->longitude);
                } else {
                    msgpack_pack_nil(&tmp_pck);
                }
                //pack longitude
                msgpack_pack_str(&tmp_pck, strlen("lat"));
                msgpack_pack_str_body(&tmp_pck,
                                      "lat",
                                      strlen("lat"));
                if (ld->latitude_found) {
                    msgpack_pack_double(&tmp_pck, ld->latitude);
                } else {
                    msgpack_pack_nil(&tmp_pck);
                }

            }
            if (ctx->include_country_code) {
                // pack code
                // free resources
                msgpack_pack_str(&tmp_pck, strlen("country"));
                msgpack_pack_str_body(&tmp_pck,
                                      "country",
                                      strlen("country"));

                if (ld->country_code_found) {
                    msgpack_pack_str(&tmp_pck, strlen(ld->country_code));
                    msgpack_pack_str_body(&tmp_pck,
                                          ld->country_code,
                                          strlen(ld->country_code));
                    flb_free(ld->country_code);
                } else {
                    msgpack_pack_nil(&tmp_pck);
                }
            }


        }

    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    flb_free(ip_string);
    return FLB_FILTER_MODIFIED;
}

static int cb_geoip_exit(void *data, struct flb_config *config) {
    struct geoip_lookup_ctx *ctx = data;

    if (ctx != NULL) {
        if (ctx->mmdb != NULL) {
            MMDB_close(ctx->mmdb);
            flb_free(ctx->mmdb);
        }
        flb_free(ctx);
    }
    return 0;
}

struct flb_filter_plugin filter_geoip_lookup_plugin = {
        .name         = "geoip_lookup",
        .description  = "geoip lookup",
        .cb_init      = cb_geoip_init,
        .cb_filter    = cb_geoip_filter,
        .cb_exit      = cb_geoip_exit,
        .flags        = 0
};
