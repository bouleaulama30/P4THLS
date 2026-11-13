import json
import os
import re
import math
from sys_utils import *
from gen_actions import (
    get_control_variable_names,
    get_user_meta_member,
    replace_variables_in_code,
    replace_p4_literals,
    extract_registers,
    transform_registers,
)


def transform_string_isvalid(input_str, headers):
    def replace_match(match):
        x = match.group(1)
        if x in headers:
            return f"pkt.isValid(H_{x.upper()})"
        return match.group(0)
    return re.sub(r'pkt\.(\w+)\.isValid\(\)', replace_match, input_str)


def transform_string_setvalid(input_str, headers):
    def replace_match(match):
        x = match.group(1)
        if x in headers:
            return f"pkt.setValid(H_{x.upper()})"
        return match.group(0)
    return re.sub(r'pkt\.(\w+)\.setValid\(\)', replace_match, input_str)


def transform_string_setinvalid(input_str, headers):
    def replace_match(match):
        x = match.group(1)
        if x in headers:
            return f"pkt.setInvalid(H_{x.upper()})"
        return match.group(0)
    return re.sub(r'pkt\.(\w+)\.setInvalid\(\)', replace_match, input_str)


def reformat_apply_block(apply_code):
    apply_pattern = re.compile(r'(\b\w+\s*\.\s*apply\s*)\(\s*\)')
    return apply_pattern.sub(r'\1(memPtr, pkt)', apply_code)


def reformat_action_calls(apply_code, actions_json):
    for action_name in actions_json.keys():
        # Match standalone calls like drop_frame() or accept_vl(1) not preceded by '.'
        pattern_empty = re.compile(rf'(?<![\.\w])\b{re.escape(action_name)}\s*\(\s*\)')
        apply_code = pattern_empty.sub(f'{action_name}(pkt)', apply_code)
        pattern_args = re.compile(rf'(?<![\.\w])\b{re.escape(action_name)}\s*\((?!\s*pkt\b)([^)]+)\)')
        apply_code = pattern_args.sub(rf'{action_name}(pkt, \1)', apply_code)
    return apply_code


def get_apply_block(p4_code):
    cleaned_code = remove_extra_empty_lines(remove_comments(p4_code))
    hdr_name, meta_name, std_meta_name = get_control_variable_names(p4_code)
    user_meta_member, scalar_fields = get_user_meta_member()
    actions_json = retrieve_object('actions')
    headers = retrieve_object('headers')

    control_block_pattern = re.compile(r'control\s+(\w+)\s*\((.*?)\)\s*\{', re.DOTALL)
    control_blocks = control_block_pattern.finditer(cleaned_code)
    code = ''
    for match in control_blocks:
        control_name = match.group(1)
        if 'ingress' not in control_name.lower():
            continue

        control_start = match.end() - 1
        control_end = find_matching_brace(cleaned_code, control_start)
        if control_end != -1:
            control_content = cleaned_code[control_start:control_end]
            apply_pattern = re.compile(r'apply\s*\{', re.DOTALL)
            apply_match = apply_pattern.search(control_content)
            if apply_match:
                apply_start = apply_match.end() - 1
                apply_end = find_matching_brace(control_content, apply_start)
                if apply_end != -1:
                    raw_apply = control_content[apply_start + 1:apply_end].strip()
                    raw_apply = re.sub(r'bit<(\d+)>', r'ap_uint<\1>', raw_apply)
                    raw_apply = replace_p4_literals(raw_apply)
                    raw_apply = replace_variables_in_code(
                        raw_apply, hdr_name, meta_name, std_meta_name,
                        user_meta_member, scalar_fields
                    )
                    raw_apply = reformat_apply_block(raw_apply)
                    raw_apply = reformat_action_calls(raw_apply, actions_json)
                    raw_apply = transform_string_isvalid(raw_apply, headers)
                    raw_apply = transform_string_setvalid(raw_apply, headers)
                    raw_apply = transform_string_setinvalid(raw_apply, headers)
                    raw_apply = transform_registers(raw_apply, extract_registers(p4_code))
                    code = beautify_code(raw_apply)
                    break
    return code


def get_top_ingress_function():
    code = '''
#if defined(STATIC)
void ingress_processing(hls::stream<Packet> &qpkt1,
                        hls::stream<Packet> &qpkt2)
{
	if (!qpkt1.empty()) {
		Packet pkt = qpkt1.read();
		ingress_control(pkt, nullptr, 0, 0);
		if (pkt.standardmetadata.drop == 0)
			qpkt2.write(pkt);
	}
}
#else
void ingress_processing(hls::stream<Packet> &qpkt1,
                        hls::stream<Packet> &qpkt2,
                        unsigned int *memCtrl,
                        unsigned int ctrl,
                        unsigned int flag)
{
#pragma HLS PIPELINE II=1
	if (!qpkt1.empty()) {
		Packet pkt = qpkt1.read();
		ingress_control(pkt, memCtrl, ctrl, flag);
		if (pkt.standardmetadata.drop == 0)
			qpkt2.write(pkt);
	}
}
#endif
'''
    return code


def get_internal_ingress_function(apply_block_code):
    tables = retrieve_object('tables')

    table_instances = []
    list_bind_uram = []
    list_bind_bram = []
    list_bind_lutram = []
    list_control_plane = []
    c = 0
    for table in tables:
        table_name = table["table_name"]
        table_struct_name = f'{table_name.capitalize()}Table'
        table_instances.append(f'static {table_struct_name} {table_name};')
        list_bind_uram.append(f'#pragma HLS bind_storage variable={table_name}.impl.lookup type=ram_2p impl=uram')
        list_bind_bram.append(f'#pragma HLS bind_storage variable={table_name}.impl.lookup type=ram_2p impl=bram')
        list_bind_lutram.append(f'#pragma HLS bind_storage variable={table_name}.impl.lookup type=ram_2p impl=lutram')
        list_control_plane.append(f'if (flag & (1 << {c})) {table_name}.update_table(memPtr, ctrl);')
        c += 1

    table_instances_code = '\n\t'.join(table_instances) + '\n\n'
    bind_storage_code = '#if defined(URAM)\n' + \
                        '\n'.join(list_bind_uram) + \
                        '\n#elif defined(BRAM)\n' + \
                        '\n'.join(list_bind_bram) + \
                        '\n#elif defined(LUTRAM)\n' + \
                        '\n'.join(list_bind_lutram) + \
                        '\n#endif\n'
    control_plane_code = '\n\t\t'.join(list_control_plane)
    code = 'inline void ingress_control(Packet &pkt, unsigned int *memPtr, unsigned int ctrl, unsigned int flag)\n{\n#pragma HLS INLINE\n\t' + \
        table_instances_code + \
        bind_storage_code + \
        '\n#if !defined(STATIC)\n    if (flag != 0) {\n\t\t' + \
        control_plane_code + \
        '\n    } else\n#endif\n    {\n' + \
        apply_block_code + \
        '\n    }\n}\n'

    return code


def gen_control_code(p4src, dir_path):
    code = '#ifndef INGRESS_PROCESSING_H\n' + \
       '#define INGRESS_PROCESSING_H\n\n' + \
       '#include "../common/Shared.h"\n' + \
       '#include "../header/Packet.h"\n' + \
       '#include "../table/Table.h"\n\n' + \
       get_internal_ingress_function(get_apply_block(p4src)) + \
       get_top_ingress_function() + \
       '\n#endif // INGRESS_PROCESSING_H\n'

    with open(f'{dir_path}/IngressProcessing.h', 'w') as f:
        f.write(code)


def generate_control(p4src, json_data, build_dir, src_dir):
    dir_path = f'{build_dir}/ingress'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    gen_control_code(p4src, dir_path)
    copy_file(f'{src_dir}/templated/MemoryInterface.h', f'{dir_path}/MemoryInterface.h')
