import json
import os


def gen_read_stream_code():
    return '''
inline bool read_stream(hls::stream<axi_chunk> &input, unsigned char *buff)
{
	if (input.empty()) {
		return false;
	}
	int count = 0;
	bool last = false;
	PS_1: while (!last && count < maxPacketBytes) {
#pragma HLS PIPELINE II=1
#pragma HLS LOOP_TRIPCOUNT min=512/BW max=512/BW avg=512/BW
		axi_chunk chunk = input.read();
		last = chunk.last;
		PS_2: for (int i = 0; i < BB; i++) {
#pragma HLS UNROLL
			if (count + i < maxPacketBytes) {
				buff[count + i] = chunk.data.range(i * 8 + 7, i * 8);
			}
		}
		count += BB;
	}

	return (count != 0);
}'''


def extract_graph(json_data):
    graph = {}
    parser = json_data['parsers'][0]
    init_state = parser.get('init_state', 'start')
    states = parser['parse_states']
    for state in states:
        name = state['name']
        transitions = state['transitions']
        next_states = []
        for trans in transitions:
            nxt = trans['next_state']
            if nxt is not None:
                next_states.append(nxt)
            else:
                next_states.append('ACCEPT')
        if not next_states:
            next_states.append('ACCEPT')
        graph[name] = next_states
    return graph, init_state


def get_level_graph(graph, init_state):
    level_graph = []
    cur_nodes = set([init_state])
    level_graph.append(cur_nodes)
    max_depth = len(graph) + 2
    depth = 0
    while (len(cur_nodes) > 1 or 'ACCEPT' not in cur_nodes) and depth < max_depth:
        depth += 1
        level_set = set()
        for node in cur_nodes:
            if node == 'ACCEPT' or node not in graph:
                level_set.add('ACCEPT')
            else:
                for nxt in graph[node]:
                    level_set.add(nxt)
        level_graph.append(level_set)
        cur_nodes = level_set

    seen_nodes = set()
    for i in range(len(level_graph) - 1, -1, -1):
        unique_nodes = set()
        for node in level_graph[i]:
            if node == 'ACCEPT':
                unique_nodes.add(node)
                continue
            elif node not in seen_nodes:
                unique_nodes.add(node)
                seen_nodes.add(node)
        level_graph[i] = unique_nodes

    return level_graph


def gen_states_code(enum_states):
    s = 'enum ParserState {\n'
    for i in range(len(enum_states)):
        s += f'    {enum_states[i]}'
        if i < len(enum_states) - 1:
            s += ','
        s += '\n'
    s += '};\n'
    return s


def gen_subparser_code(json_data, dir_path):
    code = ''
    enum_states = ['P_ACCEPT', 'P_REJECT']
    states = json_data['parsers'][0]['parse_states']
    state_names = []
    for state in states:
        st_name = state['name']
        state_names.append(st_name)
        enum_states.append(f'P_STATE_{st_name.upper()}')

    for state in states:
        st_name = state['name']
        key = state.get('transition_key', [])
        key_phrase = ''
        if key:
            key_phrase = '.'.join(key[0]['value'])

        ops = state.get('parser_ops', [])
        extract_lines = ''
        for op in ops:
            if op.get('op') == 'extract':
                header_name = op['parameters'][0]['value']
                extract_lines += f'    deserialize(&buff[offset], pkt.{header_name});\n'
                extract_lines += f'    pkt.setValid(H_{header_name.upper()});\n'
                extract_lines += f'    offset += H_{header_name.upper()}_SIZE;\n'

        transitions = state.get('transitions', [])
        trans_code = ''
        if key_phrase and transitions:
            trans_code += f'    switch (pkt.{key_phrase}.to_uint()) {{\n'
            has_default = False
            for trans in transitions:
                val = trans.get('value')
                nxt = trans.get('next_state')
                t_type = trans.get('type', '')
                nxt_enum = f'P_STATE_{nxt.upper()}' if nxt is not None else 'P_ACCEPT'
                if t_type == 'default' or val is None:
                    trans_code += f'    default: state = {nxt_enum}; break;\n'
                    has_default = True
                else:
                    trans_code += f'    case {val}: state = {nxt_enum}; break;\n'
            if not has_default:
                trans_code += '    default: state = P_ACCEPT; break;\n'
            trans_code += '    }\n'
        else:
            nxt = transitions[0].get('next_state') if transitions else None
            nxt_enum = f'P_STATE_{nxt.upper()}' if nxt is not None else 'P_ACCEPT'
            trans_code += f'    state = {nxt_enum};\n'

        parse_func = f'inline int parse_state_{st_name}(const unsigned char *buff, Packet &pkt, ParserState &state) {{\n'
        parse_func += '#pragma HLS INLINE\n'
        parse_func += '    int offset = 0;\n'
        parse_func += extract_lines
        parse_func += trans_code
        parse_func += '    return offset;\n'
        parse_func += '}\n\n'
        code += parse_func

    enum_code = gen_states_code(enum_states)

    s_begin = '''#ifndef SUB_PARSER_H
#define SUB_PARSER_H

#include "../common/Shared.h"
#include "../header/Packet.h"
'''
    s_end = '#endif // SUB_PARSER_H\n'
    full_code = f'{s_begin}\n{enum_code}\n{code}\n{s_end}'

    with open(f'{dir_path}/SubParser.h', 'w') as f:
        f.write(full_code)
    return state_names


def gen_fwd_parser_code(graph, init_state):
    code = f'''
inline bool forward_parser(Packet &pkt, const unsigned char *buff)
{{
#pragma HLS INLINE
    bool accept = false;
    bool reject = false;
    ParserState state = P_STATE_{init_state.upper()};

    int idx = 0;
'''
    for level in graph:
        layer_code = '    switch (state) {\n'
        for node in sorted(list(level)):
            if node != 'ACCEPT':
                layer_code += f'    case P_STATE_{node.upper()}: idx += parse_state_{node}(&buff[idx], pkt, state); break;\n'
        layer_code += '    case P_ACCEPT:   accept = true;    break;\n'
        layer_code += '    case P_REJECT:   reject = true;    break;\n'
        layer_code += '    default:         state = P_REJECT; break;\n'
        layer_code += '    }\n\n'
        code += layer_code

    code += '    return accept;\n}\n'
    return code


def gen_main_parser_code(json_data, dir_path, inport):
    graph, init_state = extract_graph(json_data)
    level_graph = get_level_graph(graph, init_state)
    fwd_parser_code = gen_fwd_parser_code(level_graph, init_state)
    read_stream_code = gen_read_stream_code()

    s_begin = '''#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "SubParser.h"
#include <hls_stream.h>
'''
    s_end = '''
void packet_parser(
'''
    s_end += "\n".join([f'{" " * 20}hls::stream<axi_chunk> &in{i},' for i in range(inport)])
    s_end += f'\n{" " * 20}' + '''hls::stream<Packet> &qpkt)
{
    unsigned char buff[nbInputPorts][maxPacketBytes];
#pragma HLS ARRAY_PARTITION variable=buff type=complete dim=0

    bool valid[nbInputPorts];
#pragma HLS ARRAY_PARTITION variable=valid type=complete dim=0
'''
    s_end += "\n".join([f'    valid[{i}] = read_stream(in{i}, buff[{i}]);' for i in range(inport)])
    s_end += '''
	for (int i = 0; i < nbInputPorts; i ++) {
#pragma HLS UNROLL
		if (valid[i]) {
			Packet pkt;
			forward_parser(pkt, buff[i]);
			pkt.standardmetadata.ingress_port = i;
			pkt.standardmetadata.egress_port = i;
			qpkt.write(pkt);
		}
	}
}

#endif // PACKET_PARSER_H
'''
    code = f'{s_begin}\n{read_stream_code}\n{fwd_parser_code}\n{s_end}'
    with open(f'{dir_path}/PacketParser.h', 'w') as f:
        f.write(code)
    return


def generate_parser(json_data, build_dir, inport):
    dir_path = f'{build_dir}/parser'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    gen_subparser_code(json_data, dir_path)
    gen_main_parser_code(json_data, dir_path, inport)
