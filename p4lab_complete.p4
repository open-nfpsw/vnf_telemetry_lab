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
 * P4 source for lab 2 of the Netronome DXDD demo
 */

#define ETHERTYPE_IPV4 0x0800
#define IPPROTO_TCP 6

/*
 * Header declarations
 */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type tcp_tsopt_t {
    fields {
		kind : 8;
		len : 8;
		ts_val : 32;
		ts_ect : 32;
		zero_padding : 16;
	}
}

/* metadata used for tcp checksum calculation */
header_type tcp_ipv4_metadata_t {
    fields {
        scratch : 16;
        tcpLength : 16;
    }
}

header_type intrinsic_metadata_t {
	fields {
		ingress_global_tstamp : 32;
	}
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header tcp_tsopt_t tcp_tsopt;

metadata tcp_ipv4_metadata_t tcp_ipv4_metadata;
metadata intrinsic_metadata_t intrinsic_metadata;

/* Field list calculations */

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        16'0;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

field_list tcp_ipv4_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    8'0;
    ipv4.protocol;
    tcp_ipv4_metadata.tcpLength;
    tcp.srcPort;
    tcp.dstPort;
    tcp.seqNo;
    tcp.ackNo;
    tcp.dataOffset;
    tcp.res;
    tcp.flags;
    tcp.window;
    tcp.urgentPtr;
    payload;
}

field_list_calculation tcp_ipv4_checksum {
    input {
        tcp_ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum  {
    verify tcp_ipv4_checksum if(valid(ipv4));
    update tcp_ipv4_checksum if(valid(ipv4));
}

/*
 * Parser
 */

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    /* we need to put the ip length into a 16 bit reg, as 1.0 doesn't support
     * casting and the << 2 operation user later would lose bits if done with directly
     */
    set_metadata(tcp_ipv4_metadata.scratch, ipv4.ihl);
    return select(latest.protocol) {
        IPPROTO_TCP : parse_tcp;
        default: ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    set_metadata(tcp_ipv4_metadata.tcpLength, ipv4.totalLen - (tcp_ipv4_metadata.scratch << 2));
	return select(latest.dataOffset, current(0, 8)) {
		0x0808: parse_tcp_tsopt;
		default : ingress;
	}
}

parser parse_tcp_tsopt {
    extract(tcp_tsopt);
    return ingress;
}

/*
 * Ingress
 */

primitive_action tsopt_statistics();

action do_process_tsopt() {
	tsopt_statistics();
	
	remove_header(tcp_tsopt);
	subtract_from_field(tcp.dataOffset, 3);
	subtract_from_field(tcp_ipv4_metadata.tcpLength, 12);
	subtract_from_field(ipv4.totalLen, 12);    
}

table process_tsopt {
	actions {
		do_process_tsopt;
	}
}

action do_forward(espec) {
    modify_field(standard_metadata.egress_spec, espec);
}

table forward {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
		do_forward;
    }
}

control ingress {
	if (valid(tcp_tsopt)) {
		apply(process_tsopt);
	}
    apply(forward);
}

/*
 * Egress
 */

action do_insert_tsopt() {
	add_header(tcp_tsopt);

	modify_field(tcp_tsopt.kind, 8);
	modify_field(tcp_tsopt.len, 10);
	modify_field(tcp_tsopt.ts_ect, 0);
	modify_field(tcp_tsopt.zero_padding, 0);
	modify_field(tcp_tsopt.ts_val,
				 intrinsic_metadata.ingress_global_tstamp);

	add_to_field(tcp.dataOffset, 3);
	add_to_field(tcp_ipv4_metadata.tcpLength, 12);
	add_to_field(ipv4.totalLen, 12);
}

table insert_tsopt {
	reads {
		standard_metadata.egress_port : exact;
	}
	actions {
		do_insert_tsopt;
	}
}

control egress {
	if (valid(tcp) and not valid (tcp_tsopt)) {
		apply(insert_tsopt);
	}
}