/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  ZMQ input plugin for Fluent Bit
 *  ===============================
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input_plugin.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include <czmq.h>

#include "in_zmq.h"

static int zmq_data_append(char *msg, int msg_len,
                            struct flb_input_instance *in)
{
    int i;
    int ret;
    int n_size;
    int root_type;
    size_t out;
    size_t off = 0;
    char *pack;
    msgpack_object root;
    msgpack_unpacked result;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Convert our incoming JSON to MsgPack */
    ret = flb_pack_json(msg, msg_len, &pack, &out, &root_type);
    if (ret != 0) {
        flb_plg_warn(in, "ZMQ Packet incomplete or is not JSON");
        return -1;
    }

    off = 0;
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, pack, out, &off) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    if (result.data.type != MSGPACK_OBJECT_MAP){
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    root = result.data;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);

    n_size = root.via.map.size;
    msgpack_pack_map(&mp_pck, n_size);


    /* Re-pack original KVs */
    for (i = 0; i < n_size; i++) {
        msgpack_pack_object(&mp_pck, root.via.map.ptr[i].key);
        msgpack_pack_object(&mp_pck, root.via.map.ptr[i].val);
    }


    flb_input_chunk_append_raw(in, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    msgpack_unpacked_destroy(&result);
    flb_free(pack);
    return 0;
}


static int zmq_config_read(struct flb_in_zmq_ctx *ctx,
                           struct flb_input_instance *i_ins)
{
    ctx->zmq_endpoint = flb_input_get_property("endpoint", i_ins);
    if (ctx->zmq_endpoint == NULL) {
        flb_plg_error(i_ins, "error reading 'endpoint' from configuration");
        return -1;
    }

    char *batch_size = flb_input_get_property("batch_size", i_ins);
    if (batch_size == NULL) {
        ctx->batch_size = 5000;
    } else {
        ctx->batch_size = atoi(batch_size);
        if (ctx->batch_size <= 0) {
            flb_plg_error(i_ins, "batch size has to be positive integer");
            return -1;
        }
    }

    char *schedule_nanos = flb_input_get_property("schedule_nanos", i_ins);
    if (schedule_nanos == NULL) {
        ctx->schedule_nanos = 5000;
    } else {
        ctx->schedule_nanos = atoi(schedule_nanos);
        if (ctx->schedule_nanos <= 0) {
            flb_plg_error(i_ins, "schedule_nanos size has to be positive integer");
            return -1;
        }
    }

    ctx->zmq_endpoint = flb_input_get_property("endpoint", i_ins);
    if (ctx->zmq_endpoint == NULL) {
        flb_plg_error(i_ins, "error reading 'endpoint' from configuration");
        return -1;
    }

    ctx->zmq_pull_socket = NULL;

    flb_plg_debug(i_ins, "reading configuration endpoint ='%s'", ctx->zmq_endpoint);

    return 0;
}

/* Callback triggered when some zmq msgs are available */
static int in_zmq_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context)
{
    struct flb_in_zmq_ctx *ctx = in_context;

    int counter = 0;
    zpoller_wait(ctx->zmq_poller, 50);
    while (zpoller_expired(ctx->zmq_poller) == false && zpoller_terminated(ctx->zmq_poller) == false && counter <= ctx->batch_size) {
        char *my_message = zstr_recv(ctx->zmq_pull_socket);
        zmq_data_append(my_message, strlen(my_message), in);
        flb_plg_debug(in, "message len '%d'", strlen(my_message));
        zstr_free(&my_message);
        counter++;
        zpoller_wait(ctx->zmq_poller, 50);
    }
    return 0;
}

/* Cleanup zmq input */
int in_zmq_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_zmq_ctx *ctx = in_context;
    int ret;

    flb_plg_debug(ctx->i_ins, "exiting '%s'", ctx->zmq_endpoint);

    if (ctx) {
        if (ctx->zmq_poller) {
            zpoller_destroy(&(ctx->zmq_poller));
        }
        if (ctx->zmq_pull_socket) {
            ret = zsock_unbind(ctx->zmq_pull_socket, "%s", ctx->zmq_endpoint);
            if (ret < 0 ) {
                flb_plg_error(ctx->i_ins, "zsock_unbind(%s) failed: %s", ctx->zmq_endpoint, strerror(errno));
            }
            zsock_destroy(&(ctx->zmq_pull_socket));
        }
        flb_free(ctx);
    }

    return 0;
}

/* Init zmq input */
int in_zmq_init(struct flb_input_instance *in,
                struct flb_config *config, void *data)
{
    struct flb_in_zmq_ctx *ctx = NULL;
    (void) data;

    /*
     * Disable czmq from overriding fluent-bits SIGINT/SIGTERM signal
     * handling, as prevents application from existing.
     */
    setenv("ZSYS_SIGHANDLER", "false", 1);

    ctx = flb_calloc(1, sizeof(struct flb_in_zmq_ctx));
    if (!ctx) {
        flb_plg_error(in, "flb_calloc failed: %s", strerror(errno));
        goto error;
    }

    if (zmq_config_read(ctx, in) < 0) {
        flb_plg_error(in, "zmq_config_read failed");
        goto error;
    }

    ctx->zmq_pull_socket = zsock_new(ZMQ_PULL);
    if (ctx->zmq_pull_socket == NULL) {
        flb_plg_error(in, "zsock_new failed: %s", strerror(errno));
        goto error;
    }

    ctx->zmq_poller = zpoller_new (ctx->zmq_pull_socket, NULL);
    if (ctx->zmq_poller == NULL) {
        flb_plg_error(in, "zpoller_new failed: %s", strerror(errno));
        goto error;
    }


    ctx->coll_fd = zsock_bind(ctx->zmq_pull_socket, "%s", ctx->zmq_endpoint);
    if (ctx->coll_fd < 0) {
        flb_plg_error(in, "zsock_bind(%s) failed: %s", ctx->zmq_endpoint,
                  strerror(errno));
        goto error;
    }
    flb_plg_info(in, "Binding ZMQ endpoint: '%s'", ctx->zmq_endpoint);

    /* Set our collector based on an fd event using underlying fd */
//    ret = flb_input_set_collector_event(in, in_zmq_collect, ctx->server_fd, config);
//    ret = flb_input_set_collector_socket(in, in_zmq_collect, ctx->server_fd, config);
    ctx->coll_fd = flb_input_set_collector_time(in, in_zmq_collect, 0, ctx->schedule_nanos, config);


    if (ctx->coll_fd < 0) {
        flb_plg_error(in, "flb_input_set_collector_event failed: %s",
                  strerror(errno));
        goto error;
    }

    ctx->i_ins = in;

    flb_input_set_context(in, ctx);

    return 0;

error:
    if (ctx) {
        if (ctx->zmq_poller) {
            zpoller_destroy(&(ctx->zmq_poller));
        }
        if (ctx->zmq_pull_socket)
            zsock_destroy(&(ctx->zmq_pull_socket));

        flb_free(ctx);
    }

    return -1;
}

static void in_zmq_pause(void *data, struct flb_config *config)
{
    struct flb_in_zmq_ctx *ctx = data;
    flb_plg_info(ctx->i_ins, "Pausing");
    flb_input_collector_pause(ctx->coll_fd, ctx->i_ins);
}

static void in_zmq_resume(void *data, struct flb_config *config)
{
    struct flb_in_zmq_ctx *ctx = data;
    flb_plg_info(ctx->i_ins, "Resuming");
    flb_input_collector_resume(ctx->coll_fd, ctx->i_ins);
}


/* Plugin reference */
struct flb_input_plugin in_zmq_plugin = {
    .name         = "zmq",
    .description  = "Process logs in zmq msgs",
    .cb_init      = in_zmq_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_zmq_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_zmq_pause,
    .cb_resume    = in_zmq_resume,
    .cb_exit      = in_zmq_exit
};
