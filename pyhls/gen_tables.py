import json
import os
import re
import math
from sys_utils import *


def format_ap_uint_literal(width, val_str):
    val_str = str(val_str).strip()
    if val_str.startswith('0x') or val_str.startswith('0X'):
        return f'ap_uint<{width}>("{val_str}", 16)'
    return f'ap_uint<{width}>({val_str})'


def gen_matchkey_code(key_param):
    key_width = 0
    key_widths = []
    body_code = ''
    headers = retrieve_object('headers')
    metadata = retrieve_object('metadata')

    for param in key_param:
        l = param.split('.')
        hdr = l[0].strip()
        field = l[-1].strip()
        w = 0
        access_expr = ''
        if hdr in headers and field in headers[hdr]:
            w = headers[hdr][field]
            access_expr = f'pkt.{hdr}.{field}'
        elif hdr in metadata and field in metadata[hdr]:
            w = metadata[hdr][field]
            access_expr = f'pkt.{hdr}.{field}'
        else:
            for m_name, m_fields in metadata.items():
                if field in m_fields:
                    w = m_fields[field]
                    access_expr = f'pkt.{m_name}.{field}'
                    break
        if w > 0:
            key_width += w
            key_widths.append(w)
            body_code += f'\t\tkey.range({key_width-1}, {key_width-w}) = {access_expr};\n'

    if key_width == 0:
        key_width = 1
        key_widths = [1]
        body_code = '\t\tkey = 0;\n'

    header_code = f'\tap_uint<{key_width}> get_matchkey(Packet &pkt) const {{\n#pragma HLS INLINE\n'
    body_code = f'\t\tap_uint<{key_width}> key = 0;\n' + body_code
    tail_code = '\t\treturn key;\n\t}\n'
    code = header_code + body_code + tail_code
    return code, key_width, key_widths


def build_action_call(action_name, action_info, action_data=None, from_value_expr=False, value_offset=1):
    if action_name in ['NoAction', 'Nop', '']:
        return 'NoAction(pkt);'
    args_dict = action_info.get('args', {})
    call_args = ['pkt']
    if from_value_expr:
        idx = value_offset
        for arg_name, arg_width in args_dict.items():
            call_args.append(f'value.range({arg_width + idx - 1}, {idx})')
            idx += arg_width
    else:
        data_list = action_data if action_data else []
        for i, (arg_name, arg_width) in enumerate(args_dict.items()):
            val_str = data_list[i] if i < len(data_list) else '0'
            call_args.append(format_ap_uint_literal(arg_width, val_str))
    return f'{action_name}({", ".join(call_args)});'


def gen_apply_code(table_param, actions_json, key_width, key_widths):
    num_actions = max(1, len(actions_json))
    value_width_offset = math.ceil(math.log2(num_actions + 1)) + 1
    max_value_width = 0
    default_action = table_param['default_action']
    default_data = table_param.get('default_action_data', [])

    # Build bmv2_id -> action_name map
    bmv2_to_name = {}
    for ac_name, ac_info in actions_json.items():
        for bid in ac_info.get('bmv2_ids', []):
            bmv2_to_name[bid] = ac_name

    default_info = actions_json.get(default_action, {'args': {}})
    default_call = f'\t\t{build_action_call(default_action, default_info, default_data, from_value_expr=False)}\n'

    switch_code = '\t\t\tswitch (action_id) {\n'
    action_names = table_param['actions']
    for action_name, action_info in actions_json.items():
        if action_name in action_names:
            total_width = action_info['total_width']
            if max_value_width < total_width:
                max_value_width = total_width
            call_str = build_action_call(action_name, action_info, from_value_expr=True, value_offset=value_width_offset)
            switch_code += f'\t\t\tcase {action_info["id"]}: {call_str} break;\n'
    switch_code += '\t\t\tdefault: break;\n\t\t\t}\n'
    max_value_width += value_width_offset

    # Generate static entries matching if present in P4 (const entries)
    entries = table_param.get('entries', [])
    static_code = ''
    if entries:
        for idx_e, entry in enumerate(entries):
            match_keys = entry.get('match_key', [])
            conds = []
            cur_offset = 0
            for k_idx, mk in enumerate(match_keys):
                w = key_widths[k_idx] if k_idx < len(key_widths) else key_width
                k_val = mk.get('key', '0')
                m_type = mk.get('match_type', 'exact')
                slice_expr = f'key.range({cur_offset + w - 1}, {cur_offset})' if len(key_widths) > 1 else 'key'
                lit_expr = format_ap_uint_literal(w, k_val)
                if m_type == 'ternary' and mk.get('mask'):
                    mask_expr = format_ap_uint_literal(w, mk['mask'])
                    conds.append(f'(({slice_expr} & {mask_expr}) == ({lit_expr} & {mask_expr}))')
                else:
                    conds.append(f'({slice_expr} == {lit_expr})')
                cur_offset += w
            cond_str = ' && '.join(conds) if conds else 'true'
            act_entry = entry.get('action_entry', {})
            act_id = act_entry.get('action_id')
            act_data = act_entry.get('action_data', [])
            act_name = bmv2_to_name.get(act_id, default_action)
            act_info = actions_json.get(act_name, {'args': {}})
            act_call = build_action_call(act_name, act_info, act_data, from_value_expr=False)
            prefix = 'if' if idx_e == 0 else 'else if'
            static_code += f'\t\t{prefix} ({cond_str}) {{\n\t\t\t{act_call}\n\t\t\treturn true;\n\t\t}}\n'

    header_code = '\tbool apply(const unsigned int *memPtr, Packet &pkt) {\n#pragma HLS INLINE\n'
    body_code = f'\t\tconst ap_uint<{key_width}> key = get_matchkey(pkt);\n'
    if static_code:
        body_code += static_code
        body_code += f'#if defined(STATIC)\n{default_call}\t\treturn false;\n#else\n'
    else:
        body_code += f'#if defined(STATIC)\n{default_call}\t\treturn false;\n#else\n'

    action_id_line = f'\t\t\tauto action_id = value.range({value_width_offset-1}, 1).to_uint();\n'
    if_code = f'\t\tif (found) {{\n{action_id_line}{switch_code}\t\t}}'
    else_code = f' else {{\n\t{default_call}\t\t}}\n'
    body_code += f'\t\tap_uint<{max_value_width}> value = 0;\n'
    body_code += '\t\tbool found = impl.search_entry(memPtr, key, value);\n'
    body_code += if_code + else_code
    body_code += '\t\treturn found;\n#endif\n\t}\n'
    body_code += '\tbool apply(Packet &pkt) {\n#pragma HLS INLINE\n\t\treturn apply(nullptr, pkt);\n\t}\n'

    code = header_code + body_code
    return code, max_value_width


def gen_update_code(key_width, value_width):
    code = '''
#if !defined(STATIC)
	void update_table(unsigned int *memCtrl, unsigned int &ctrl) {
		const unsigned char func_type = static_cast<unsigned char>(ctrl & 0x0FF);
		const short entry_count = static_cast<short>((ctrl >> 8) & 0x0FFFF);
		for (int i = 0; i < entry_count; i ++) {
			'''
    nb_words = math.ceil((key_width + value_width) / 32)
    code += f'ap_uint<{32 * nb_words}> entry(0);\n\t\t\t'
    lines = []
    for j in range(nb_words):
        high = (j + 1) * 32 - 1
        low = j * 32
        lines.append(f'entry.range({high}, {low}) = memCtrl[i * {nb_words} + {j}];')

    code += '\n\t\t\t'.join(lines)
    code += '\n\t\t\tif (func_type & 0x01) {\n'
    code += f'\t\t\t\timpl.insert_entry(memCtrl, entry.range({key_width+value_width-1}, {value_width}), entry.range({value_width-1}, 0));\n'
    code += '\t\t\t} else if (func_type & 0x02) {\n'
    code += f'\t\t\t\timpl.delete_entry(memCtrl, entry.range({key_width+value_width-1}, {value_width}), entry.range({value_width-1}, 0));\n'
    code += '\t\t\t}\n\t\t}\n\t}\n'
    code += '#endif\n'

    return code


def gen_tables_code(params, dir_path):
    actions_json = retrieve_object('actions')
    t_sizes = {}
    t_key_widths = {}
    t_value_width = {}
    t_types = []
    includes_list = []

    for param in params:
        table_name = param["table_name"]
        table_struct_name = f'{table_name.capitalize()}Table'
        ctor_code = f'\t{table_struct_name}() {{}}\n'
        dtor_code = f'\t~{table_struct_name}() {{}}\n'
        matchkey_code, key_width, key_widths = gen_matchkey_code(param['key'])
        apply_code, value_width = gen_apply_code(param, actions_json, key_width, key_widths)
        update_code = gen_update_code(key_width, value_width)
        impl_code = f'#if !defined(STATIC)\n\tMatchActionTable<TS_{table_struct_name}, MS_{table_struct_name}, AS_{table_struct_name}, TYPE_{table_struct_name}> impl;\n#endif'

        t_sizes[f'TS_{table_struct_name}'] = param["size"]
        t_key_widths[f'MS_{table_struct_name}'] = key_width
        t_value_width[f'AS_{table_struct_name}'] = value_width
        t_types.append(f'TYPE_{table_struct_name}')

        table_code = f'#ifndef {table_name.upper()}_TABLE_H\n' + \
           f'#define {table_name.upper()}_TABLE_H\n\n' + \
           f'#include "MatchActionTable.h"\n\n' + \
           f'#include "../ingress/Actions.h"\n\n' + \
           f'class {table_struct_name} {{\npublic:\n' + \
           ctor_code + dtor_code + matchkey_code + apply_code + update_code + impl_code + '\n};\n\n' + \
           f'#endif // {table_name.upper()}_TABLE_H\n'

        with open(f'{dir_path}/{table_struct_name}.h', 'w') as f:
            f.write(table_code)

        includes_list.append(f'#include "{table_struct_name}.h"')

    table_header = '#ifndef TABLE_H\n' + \
                   '#define TABLE_H\n\n' + \
                   '\n'.join(includes_list) + \
                   '\n\n#endif // TABLE_H\n'
    with open(f'{dir_path}/Table.h', 'w') as f:
        f.write(table_header)

    table_const = {
        'table_size': t_sizes,
        'table_matchkey_width': t_key_widths,
        'table_action_width': t_value_width,
        'table_types': t_types
    }
    store_object(table_const, 'table_const')


def extract_explicit_table_names(p4_code):
    cleaned = remove_comments(p4_code)
    tables_names = []
    table_start_pattern = re.compile(r'table\s+(\w+)\s*\{')
    index = 0
    while index < len(cleaned):
        match = table_start_pattern.search(cleaned, index)
        if not match:
            break
        index = match.end()
        matched = match.group(1).strip()
        tables_names.append(matched)
    return tables_names


def extract_table_params_v2(p4src, json_data):
    params = []
    table_names = extract_explicit_table_names(p4src)

    # Map global action id -> short name
    global_id_to_action = {}
    for act in json_data.get('actions', []):
        global_id_to_action[act.get('id')] = act.get('name', '').split('.')[-1]

    pipes = json_data.get('pipelines', [])
    for pipe in pipes:
        tables = pipe.get('tables', [])
        for table in tables:
            t_name = table['name'].split('.')[-1]
            if t_name not in table_names:
                continue
            t_max_size = table.get('max_size', 64)
            t_action_names = [ac.split('.')[-1] for ac in table.get('actions', [])]
            t_action_ids = table.get('action_ids', [])
            t_actions = {ac: ac_id for ac, ac_id in zip(t_action_names, t_action_ids)}
            t_keys = []
            for key in table.get('key', []):
                target = '.'.join(key['target'])
                t_keys.append(target)

            t_default_action = 'NoAction'
            default_entry = table.get('default_entry', {})
            t_default_id = default_entry.get('action_id')
            t_default_data = default_entry.get('action_data', [])
            if t_default_id in global_id_to_action:
                t_default_action = global_id_to_action[t_default_id]
            else:
                for ac_name, ac_id in t_actions.items():
                    if ac_id == t_default_id:
                        t_default_action = ac_name

            t_entries = table.get('entries', [])

            params.append({
                'table_name': t_name,
                'key': t_keys,
                'actions': t_actions,
                'size': t_max_size,
                'default_action': t_default_action,
                'default_action_data': t_default_data,
                'entries': t_entries
            })
    store_object(params, 'tables')
    return params


def generate_tables(p4src, json_data, build_dir, src_dir):
    dir_path = f'{build_dir}/table'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    params = extract_table_params_v2(p4src, json_data)
    gen_tables_code(params, dir_path)
    copy_file(f'{src_dir}/templated/MatchActionTable.h', f'{dir_path}/MatchActionTable.h')
