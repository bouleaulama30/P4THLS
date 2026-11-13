import json
import os


def gen_subdeparser_code(json_data, dir_path):
    code = ''
    order = json_data['deparsers'][0]['order'] if json_data.get('deparsers') else []
    for node in order:
        code += f'    if (pkt.isValid(H_{node.upper()})) {{\n'
        code += f'        serialize(&d[count], pkt.{node});\n'
        code += f'        count += H_{node.upper()}_SIZE;\n'
        code +=  '    }\n'

    s_begin = '''#ifndef SUB_DEPARSER_H
#define SUB_DEPARSER_H

#include "../common/Shared.h"
#include "../header/Packet.h"

inline int do_deparser(unsigned char *d, Packet &pkt)
{
#pragma HLS INLINE
	int count = 0;
'''
    s_end = '\treturn count;\n}\n\n#endif // SUB_DEPARSER_H\n'
    full_code = f'{s_begin}\n{code}\n{s_end}'

    with open(f'{dir_path}/SubDeparser.h', 'w') as f:
        f.write(full_code)
    return


def gen_main_deparser_code(json_data, dir_path, outport):
    code = '''#ifndef PACKET_DEPARSER_H
#define PACKET_DEPARSER_H

#include "SubDeparser.h"
#include <hls_stream.h>
'''
    code += '''
void packet_deparser(
'''
    code += "\n".join([f'{" " * 22}hls::stream<axi_chunk> &out{i},' for i in range(outport)])
    code += f'\n{" " * 22}' + '''hls::stream<Packet> &qpkt)
{
#if defined(__SYNTHESIS__)
	if (!qpkt.empty()) {
#else
	while (!qpkt.empty()) {
#endif
		Packet pkt = qpkt.read();
		const int egress_port = pkt.standardmetadata.egress_port.to_uint();
		unsigned char d[maxPacketBytes];
#pragma HLS ARRAY_PARTITION variable=d type=complete dim=0
		for (int z = 0; z < maxPacketBytes; z++) {
#pragma HLS UNROLL
			d[z] = 0;
		}
		int count = do_deparser(d, pkt);
		if (count > 0) {
			const int chunk_count = (count + BB - 1) / BB;
			DS_1: for (int n = 0; n < chunk_count; n ++) {
#pragma HLS PIPELINE II=1
#pragma HLS LOOP_TRIPCOUNT min=1 max=PACKET_SIZE/BB avg=8
				axi_chunk chunk;
				DS_2: for (int i = 0; i < BB; i ++) {
#pragma HLS UNROLL
					chunk.data.range(i * 8 + 7, i * 8) = d[n * BB + i];
				}
				chunk.last = ((n + 1) == chunk_count) ? 1 : 0;
				int rem = count - n * BB;
				chunk.keep = chunk.last ? ap_uint<BB>((ap_uint<BB+1>(1) << rem) - 1) : ONES;
				chunk.strb = chunk.keep;
				chunk.user = 0;
				chunk.id = 0;
				chunk.dest = egress_port;
'''

    lines = []
    if outport == 1:
        lines.append(f"{' ' * 16}out0.write(chunk);")
    else:
        for i in reversed(range(outport)):
            if i == outport - 1:
                lines.append(f"{' ' * 16}if (egress_port == {i})")
            elif i > 0:
                lines.append(f"{' ' * 16}else if (egress_port == {i})")
            else:
                lines.append(f"{' ' * 16}else")
            lines.append(f"{' ' * 20}out{i}.write(chunk);")

    code += "\n".join(lines)

    code += '''
			}
		}
	}
}

#endif // PACKET_DEPARSER_H
'''
    with open(f'{dir_path}/PacketDeparser.h', 'w') as f:
        f.write(code)
    return


def generate_deparser(json_data, build_dir, outport):
    dir_path = f'{build_dir}/deparser'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    gen_subdeparser_code(json_data, dir_path)
    gen_main_deparser_code(json_data, dir_path, outport)
