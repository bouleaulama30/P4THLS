import json
import os
from sys_utils import *


def generate_serialize_function(header_name, fields):
    serialize_code = f"inline void serialize(unsigned char* d, const {header_name} &hdr) {{\n"
    serialize_code += "#pragma HLS INLINE\n"

    byte_offset = 0
    bit_offset = 0

    for field, bitwidth in fields:
        total_w = bitwidth
        rem = bitwidth
        while rem > 0:
            avail = 8 - bit_offset
            take = min(rem, avail)
            hi = rem - 1
            lo = rem - take
            shift = avail - take
            mask = (1 << take) - 1

            if total_w == take:
                expr = f"static_cast<unsigned char>(hdr.{field}.to_uint())"
            else:
                expr = f"static_cast<unsigned char>(hdr.{field}.range({hi}, {lo}).to_uint())"

            op = "=" if bit_offset == 0 else "|="

            if take == 8:
                serialize_code += f"    d[{byte_offset}] = {expr};\n"
            elif shift == 0:
                serialize_code += f"    d[{byte_offset}] {op} ({expr} & 0x{mask:X});\n"
            else:
                serialize_code += f"    d[{byte_offset}] {op} (({expr} & 0x{mask:X}) << {shift});\n"

            rem -= take
            bit_offset += take
            if bit_offset == 8:
                byte_offset += 1
                bit_offset = 0

    serialize_code += "}\n"
    return serialize_code


def generate_deserialize_function(header_name, fields):
    deserialize_code = f"inline void deserialize(const unsigned char* d, {header_name} &hdr) {{\n"
    deserialize_code += "#pragma HLS INLINE\n"

    byte_offset = 0
    bit_offset = 0

    for field, bitwidth in fields:
        total_w = bitwidth
        rem = bitwidth
        while rem > 0:
            avail = 8 - bit_offset
            take = min(rem, avail)
            hi = rem - 1
            lo = rem - take
            shift = avail - take
            mask = (1 << take) - 1

            if total_w == take:
                target = f"hdr.{field}"
            else:
                target = f"hdr.{field}.range({hi}, {lo})"

            if take == 8:
                deserialize_code += f"    {target} = d[{byte_offset}];\n"
            elif shift == 0:
                deserialize_code += f"    {target} = (d[{byte_offset}] & 0x{mask:X});\n"
            else:
                deserialize_code += f"    {target} = ((d[{byte_offset}] >> {shift}) & 0x{mask:X});\n"

            rem -= take
            bit_offset += take
            if bit_offset == 8:
                byte_offset += 1
                bit_offset = 0

    deserialize_code += "}\n"
    return deserialize_code


def get_header_size(headers, header_name):
    header = headers.get(header_name, {})
    size = 0
    if header:
        for item in header.items():
            size += item[1]
    return int((size + 7) // 8)


def extract_headers(data):
    headers = {}
    header_types = {ht['name']: ht['fields'] for ht in data['header_types']}
    for header in data['headers']:
        if header['metadata'] == False:
            header_name = header['name']
            fields = header_types.get(header['header_type'], [])
            headers[header_name] = {field[0]: field[1] for field in fields}
    return headers


def gen_base_header(dir_path):
    code = "#ifndef BASE_HEADER_H\n" + \
           "#define BASE_HEADER_H\n\n" + \
           "#include <ap_int.h>\n\n" + \
           "#endif // BASE_HEADER_H\n"
    with open(f'{dir_path}/BaseHeader.h', 'w') as f:
        f.write(code)


def gen_cpp_code(headers, dir_path):
    gen_base_header(dir_path)
    for header_name, fields in headers.items():
        header_struct_name = f'{header_name.capitalize()}Header'
        init_list = ", ".join([f"{field_name}(0)" for field_name, _ in list(fields.items())])
        if init_list:
            ctor_code = f"\t{header_struct_name}() : {init_list} {{}}\n"
        else:
            ctor_code = f"\t{header_struct_name}() {{}}\n"
        x1 = ",\n".join([f"\t\t{field_name}(other.{field_name})" for field_name, _ in list(fields.items())])
        if x1:
            copy_ctor_code = f"\t{header_struct_name}(const {header_struct_name} &other) :\n" + x1 + " {}\n"
        else:
            copy_ctor_code = f"\t{header_struct_name}(const {header_struct_name} &other) {{}}\n"
        fields_code = "\n".join([f"\tap_uint<{bitwidth}> {field_name};" for field_name, bitwidth in list(fields.items())])
        serialize_code = generate_serialize_function(header_struct_name, list(headers[header_name].items()))
        deserialize_code = generate_deserialize_function(header_struct_name, list(headers[header_name].items()))
        header_code = f"#ifndef {header_name.upper()}_HEADER_H\n" + \
           f"#define {header_name.upper()}_HEADER_H\n\n" + \
           f"#include \"BaseHeader.h\"\n\n" + \
           f"#define H_{header_name.upper()}_SIZE {get_header_size(headers, header_name)}\n\n" + \
           f"struct {header_struct_name} {{\n" + \
           f"{ctor_code}" + f"{copy_ctor_code}" + "\n" + f"{fields_code}" + "\n};\n\n" + \
           serialize_code + "\n" + deserialize_code + "\n" + \
           f"#endif // {header_name.upper()}_HEADER_H\n"

        with open(f'{dir_path}/{header_struct_name}.h', 'w') as f:
            f.write(header_code)


def generate_headers(json, build_dir):
    dir_path = f'{build_dir}/header'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    headers = extract_headers(json)
    gen_cpp_code(headers, dir_path)
    store_object(headers, 'headers')
