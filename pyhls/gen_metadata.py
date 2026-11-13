import json
import os
from sys_utils import *


def generate_serialize_function(meta_name, fields):
    serialize_code = f"inline void serialize(unsigned char* d, const {meta_name} &hdr) {{\n"
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


def generate_deserialize_function(meta_name, fields):
    deserialize_code = f"inline void deserialize(const unsigned char* d, {meta_name} &hdr) {{\n"
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


def sanitize_field_name(name):
    return name.split('.')[-1].replace('$', '_')


def extract_metadata(data):
    metadata = {}
    header_types = {ht['name']: ht['fields'] for ht in data['header_types']}
    for meta in data['headers']:
        if meta['metadata'] == True:
            meta_name = meta['name']
            if 'standard' in meta_name.lower():
                continue
            fields = header_types.get(meta['header_type'], [])
            metadata[meta_name] = {sanitize_field_name(field[0]): field[1] for field in fields}
    return metadata


def extract_std_metadata():
    std_metadata = {}
    std_metadata['ingress_port'] = 9
    std_metadata['egress_spec'] = 9
    std_metadata['egress_port'] = 9
    std_metadata['drop'] = 1
    std_metadata['_padding'] = 4
    return std_metadata


def gen_cpp_code(headers, dir_path):
    for meta_name, fields in headers.items():
        meta_struct_name = f'{meta_name.capitalize()}'
        init_list = ", ".join([f"{field_name}(0)" for field_name, _ in list(fields.items())])
        if init_list:
            ctor_code = f"\t{meta_struct_name}() : {init_list} {{}}\n"
        else:
            ctor_code = f"\t{meta_struct_name}() {{}}\n"
        x1 = ",\n".join([f"\t\t{field_name}(other.{field_name})" for field_name, _ in list(fields.items())])
        if x1:
            copy_ctor_code = f"\t{meta_struct_name}(const {meta_struct_name} &other) :\n" + x1 + " {}\n"
        else:
            copy_ctor_code = f"\t{meta_struct_name}(const {meta_struct_name} &other) {{}}\n"
        fields_code = "\n".join([f"\tap_uint<{bitwidth}> {field_name};" for field_name, bitwidth in list(fields.items())])
        serialize_code = generate_serialize_function(meta_struct_name, list(headers[meta_name].items()))
        deserialize_code = generate_deserialize_function(meta_struct_name, list(headers[meta_name].items()))
        metadata_code = f"#ifndef {meta_name.upper()}_H\n" + \
           f"#define {meta_name.upper()}_H\n\n" + \
           f"#include \"BaseHeader.h\"\n\n" + \
           f"struct {meta_struct_name} {{\n" + \
           f"{ctor_code}" + f"{copy_ctor_code}" + "\n" + f"{fields_code}" + "\n};\n\n" + \
           serialize_code + "\n" + deserialize_code + "\n" + \
           f"#endif // {meta_name.upper()}_H\n"

        with open(f'{dir_path}/{meta_struct_name}.h', 'w') as f:
            f.write(metadata_code)


def generate_metadata(json, build_dir):
    dir_path = f'{build_dir}/header'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    metadata = extract_metadata(json)
    metadata['standardmetadata'] = extract_std_metadata()
    gen_cpp_code(metadata, dir_path)
    store_object(metadata, 'metadata')
