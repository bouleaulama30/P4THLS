import json
import os
import re
from sys_utils import *


def replace_p4_literals(code):
    code = re.sub(r'\b(\d+)w0x([0-9a-fA-F_]+)\b', lambda m: f'ap_uint<{m.group(1)}>("0x{m.group(2).replace("_", "")}", 16)', code)
    code = re.sub(r'\b(\d+)w(\d+)\b', r'ap_uint<\1>(\2)', code)
    code = re.sub(r'(\w+)\s*\[\s*(\d+)\s*:\s*(\d+)\s*\]', r'\1.range(\2, \3)', code)
    return code


def get_control_variable_names(p4src):
    cleaned = remove_comments(p4src)
    hdr_name = 'hdr'
    meta_name = 'meta'
    std_meta_name = 'standard_metadata'

    control_pattern = re.compile(r'control\s+(\w+)\s*\((.*?)\)\s*\{', re.DOTALL)
    for match in control_pattern.finditer(cleaned):
        cname = match.group(1)
        if 'ingress' in cname.lower():
            args = match.group(2)
            m_hdr = re.search(r'inout\s+headers\s+(\w+)', args)
            if m_hdr:
                hdr_name = m_hdr.group(1)
            m_meta = re.search(r'inout\s+metadata\s+(\w+)', args)
            if m_meta:
                meta_name = m_meta.group(1)
            m_std = re.search(r'inout\s+standard_metadata_t\s+(\w+)', args)
            if m_std:
                std_meta_name = m_std.group(1)
            break
    return hdr_name, meta_name, std_meta_name


def get_user_meta_member():
    try:
        metadata = retrieve_object('metadata')
        for k in metadata.keys():
            if k != 'standardmetadata':
                return k, list(metadata[k].keys())
    except Exception:
        pass
    return 'scalars', []


def extract_action_definition(p4_code, action_name, action_args):
    if action_name == 'NoAction':
        return 'inline void NoAction(Packet &pkt) {\n#pragma HLS INLINE\n}'
    cleaned = remove_comments(p4_code)
    pattern1 = re.compile(rf'action\s+{re.escape(action_name)}\s*\((.*?)\)\s*\{{', re.DOTALL)
    match = pattern1.search(cleaned)
    if match:
        open_brace_idx = match.end() - 1
        close_brace_idx = find_matching_brace(cleaned, open_brace_idx)
        if close_brace_idx == -1:
            return ''
        raw_body = cleaned[open_brace_idx + 1:close_brace_idx]
        action_header = 'Packet &pkt'
        for arg_name, arg_width in action_args.items():
            action_header = f'{action_header}, ap_uint<{arg_width}> {arg_name}'
        action_header = f'inline void {action_name}({action_header}) {{\n#pragma HLS INLINE'
        action_body = f'\t{raw_body.strip()}'
        action_body = re.sub(r'\n\s*\n+', '\n', action_body)

        pattern2 = r'bit<(\d+)>'
        action_body = re.sub(pattern2, r'ap_uint<\1>', action_body)
        action_body = replace_p4_literals(action_body)

        action_code = f'{action_header}\n{action_body}\n}}'
        return action_code
    else:
        return ''


def replace_variables_in_code(code, hdr_name, meta_name, std_meta_name, user_meta_member, scalar_fields, arg_names=None):
    if arg_names is None:
        arg_names = []
    # Replace mark_to_drop(...)
    code = re.sub(r'mark_to_drop\s*\(\s*\w*\s*\)', 'pkt.standardmetadata.drop = 1', code)
    # Replace hdr., meta., standard_metadata.
    if hdr_name:
        code = re.sub(rf'\b{hdr_name}\b(?=\s*[\.\[])', 'pkt', code)
    if meta_name:
        code = re.sub(rf'\b{meta_name}\b(?=\s*[\.\[])', f'pkt.{user_meta_member}', code)
    if std_meta_name:
        code = re.sub(rf'\b{std_meta_name}\b(?=\s*[\.\[])', 'pkt.standardmetadata', code)

    # Replace bare scalar fields (e.g. local bool ip_allowed in control block)
    for sf in scalar_fields:
        if sf in arg_names:
            continue
        code = re.sub(rf'(?<![\.\w])\b{re.escape(sf)}\b(?!\s*\()', f'pkt.{user_meta_member}.{sf}', code)

    return code


def replace_setValid(action_code):
    pattern = r'pkt\.(\w+)\.setValid\(\);'
    def replacer(match):
        header_type = match.group(1)
        return f'pkt.setValid(H_{header_type.upper()});'
    return re.sub(pattern, replacer, action_code)


def replace_setInvalid(action_code):
    pattern = r'pkt\.(\w+)\.setInvalid\(\);'
    def replacer(match):
        header_type = match.group(1)
        return f'pkt.setInvalid(H_{header_type.upper()});'
    return re.sub(pattern, replacer, action_code)


def extract_registers(p4_code):
    cleaned = remove_comments(p4_code)
    regs = []
    for m in re.finditer(r'register\s*<\s*bit\s*<\s*(\d+)\s*>\s*>\s*\(\s*(\d+)\s*\)\s*(\w+)\s*;', cleaned):
        width = int(m.group(1))
        size = int(m.group(2))
        name = m.group(3)
        regs.append((name, width, size))
    return regs


def transform_registers(code, regs):
    for name, _, _ in regs:
        code = re.sub(
            rf'\b{re.escape(name)}\s*\.\s*read\s*\(\s*([^,]+?)\s*,\s*([^;]+?)\s*\)\s*;',
            rf'\1 = {name}[\2];',
            code
        )
        code = re.sub(
            rf'\b{re.escape(name)}\s*\.\s*write\s*\(\s*([^,]+?)\s*,\s*([^;]+?)\s*\)\s*;',
            rf'{name}[\1] = \2;',
            code
        )
    return code


def extract_actions(p4src, json_data):
    actions_with_code = {}
    hdr_name, meta_name, std_meta_name = get_control_variable_names(p4src)
    user_meta_member, scalar_fields = get_user_meta_member()
    regs = extract_registers(p4src)
    actions = json_data.get("actions", [])
    actions_json = {}
    action_id = 0

    for action in actions:
        raw_name = action.get('name', '')
        bmv2_id = action.get('id')
        parts = raw_name.split('.')
        action_abs_name = parts[-1]
        if action_abs_name in ['Nop', 'NoAction'] or 'NoAction' in action_abs_name:
            action_abs_name = 'NoAction'

        if action_abs_name in actions_json:
            if bmv2_id is not None and bmv2_id not in actions_json[action_abs_name]['bmv2_ids']:
                actions_json[action_abs_name]['bmv2_ids'].append(bmv2_id)
            continue

        action_args = {ht['name']: ht['bitwidth'] for ht in action.get('runtime_data', [])}
        if not action_args:
            cleaned_src = remove_comments(p4src)
            sig_m = re.search(rf'action\s+{re.escape(action_abs_name)}\s*\((.*?)\)\s*\{{', cleaned_src, re.DOTALL)
            if sig_m and sig_m.group(1).strip():
                for param_decl in sig_m.group(1).split(','):
                    pm = re.search(r'bit<\s*(\d+)\s*>\s+(\w+)', param_decl)
                    if pm:
                        action_args[pm.group(2)] = int(pm.group(1))
        code_step1 = extract_action_definition(p4src, action_abs_name, action_args)
        if code_step1:
            # Transform only the body inside braces so function signature is untouched
            brace_pos = code_step1.find('{')
            sig = code_step1[:brace_pos + 1]
            body = code_step1[brace_pos + 1:]
            body = replace_variables_in_code(
                body, hdr_name, meta_name, std_meta_name,
                user_meta_member, scalar_fields, list(action_args.keys())
            )
            body = replace_setValid(body)
            body = replace_setInvalid(body)
            body = transform_registers(body, regs)
            final_code = sig + body
            actions_with_code[action_abs_name] = final_code
            total_width = sum(action_args.values())
            actions_json[action_abs_name] = {
                'id': action_id,
                'bmv2_ids': [bmv2_id] if bmv2_id is not None else [],
                'total_width': total_width,
                'args': action_args
            }
            action_id += 1

    cleaned_src = remove_comments(p4src)
    for act_m in re.finditer(r'action\s+(\w+)\s*\((.*?)\)\s*\{', cleaned_src, re.DOTALL):
        action_abs_name = act_m.group(1).strip()
        if action_abs_name in actions_json or action_abs_name in ['NoAction', 'Nop']:
            continue
        action_args = {}
        if act_m.group(2).strip():
            for param_decl in act_m.group(2).split(','):
                pm = re.search(r'bit<\s*(\d+)\s*>\s+(\w+)', param_decl)
                if pm:
                    action_args[pm.group(2)] = int(pm.group(1))
        code_step1 = extract_action_definition(p4src, action_abs_name, action_args)
        if code_step1:
            brace_pos = code_step1.find('{')
            sig = code_step1[:brace_pos + 1]
            body = code_step1[brace_pos + 1:]
            body = replace_variables_in_code(
                body, hdr_name, meta_name, std_meta_name,
                user_meta_member, scalar_fields, list(action_args.keys())
            )
            body = replace_setValid(body)
            body = replace_setInvalid(body)
            body = transform_registers(body, regs)
            final_code = sig + body
            actions_with_code[action_abs_name] = final_code
            actions_json[action_abs_name] = {
                'id': action_id,
                'bmv2_ids': [],
                'total_width': sum(action_args.values()),
                'args': action_args
            }
            action_id += 1

    store_object(actions_json, 'actions')
    return actions_with_code, regs


def gen_actions_code(actions, regs, dir_path):
    s_begin = '''#ifndef ACTIONS_H
#define ACTIONS_H

#include "../header/Packet.h"
'''
    s_end = '#endif // ACTIONS_H\n'
    s_regs = ''
    for name, width, size in regs:
        s_regs += f'static ap_uint<{width}> {name}[{size}];\n'
    if s_regs:
        s_regs += '\n'
    s_body = ''
    for name, body in actions.items():
        if body:
            s_body += f'{body}\n\n'
    code = f'{s_begin}\n{s_regs}{s_body}{s_end}'
    with open(f'{dir_path}/Actions.h', 'w') as f:
        f.write(code)
    return


def generate_actions(p4src, json_data, build_dir):
    dir_path = f'{build_dir}/ingress'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    actions, regs = extract_actions(p4src, json_data)
    gen_actions_code(actions, regs, dir_path)
