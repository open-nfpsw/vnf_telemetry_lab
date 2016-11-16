/*
 * Copyright (C) 2016, Netronome Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

/*
 * C Sandbox source code DXDD 2016
 *
 * pif_plugin_tsopt_statistics() :
 *      Process TCP timestamp optional header
 *
 */

#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include "pif_plugin.h"

/*
 * TCP time operation
 */

/* ingress_port is a 10-bit value */
#define PORTMAX 1024

/* data structure for latency data per port */
struct tsopt_data {
    uint64_t max_latency;
    uint64_t min_latency;
    uint64_t count;
    uint64_t total_latency;
};

/* declare latency data with one extra slot for bad port#
 * this memory is exported so we can get to it from the host
 */
__export __mem struct tsopt_data tsopt_data[PORTMAX + 1];

int pif_plugin_tsopt_statistics(EXTRACTED_HEADERS_T *headers,
                                MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_tcp_tsopt_T *tsopt = pif_plugin_hdr_get_tcp_tsopt(headers);
    __xread struct tsopt_data in_xfer;
    __gpr struct tsopt_data out_reg;
    __xwrite struct tsopt_data out_xfer;
    uint32_t ctime, ptime;
    uint32_t latency;
    unsigned port;

    /* Get the time at parsing from the intrinsic metadata timestamp */
    ctime = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp(headers);

    /* Retrieve ingress port from P4 metadata */
    port = pif_plugin_meta_get__standard_metadata__ingress_port(headers);

    /* we don't error out here, we just use use a reserved bucket */
    if (port >= PORTMAX)
        port = PORTMAX;

    /* Retrieve the previous time from the tsopt header field */
    ptime = PIF_HEADER_GET_tcp_tsopt___ts_val(tsopt);

    /* this assumes no wrapping takes place, which should only occur if the
     * latency is in the order of tens of seconds
     */
    latency = ctime - ptime;

    /* grab the option data for this port */
    mem_read32(&in_xfer, &tsopt_data[port], sizeof(in_xfer));

    out_reg = in_xfer;

    if (latency > out_reg.max_latency)
        out_reg.max_latency = latency;

    if (latency < out_reg.min_latency || out_reg.min_latency == 0)
        out_reg.min_latency = latency;

    out_reg.count += 1;
    out_reg.total_latency += latency;

    out_xfer = out_reg;
    mem_write32(&out_xfer, &tsopt_data[port], sizeof(out_xfer));

    return PIF_PLUGIN_RETURN_FORWARD;
}
