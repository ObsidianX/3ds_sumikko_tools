#!/usr/bin/python

import argparse
import json
import re
import struct

BIN_NAME = 'systemtext.bin'
JSON_NAME = 'systemtext.json'


def find_end(data):
    position = 0
    while position < len(data):
        if data[position:position + 2] == '\x00\x00':
            return position
        position += 2

    return -1


def extract_bin():
    data = open(BIN_NAME, 'rb').read()
    position = 0

    count = struct.unpack('<H', data[:2])[0]
    position += 2

    offsets = struct.unpack('<%dH' % count, data[position:position + (2 * count)])

    strings = []

    for idx in range(len(offsets)):
        if offsets[idx] == 0xFFFF:
            strings.append(None)
            continue

        start = offsets[idx]
        end = start + find_end(data[start:])

        raw_string = data[start:end]

        string = raw_string.replace('\x0b\x00col1', '{col1}'.encode('utf-16-le'))
        string = string.replace('\x0b\x00ruby', '{ruby}'.encode('utf-16-le'))
        string = string.replace('\x0b\x00', '{reset}'.encode('utf-16-le'))

        strings.append(string.decode('utf-16'))

    output = open(JSON_NAME, 'wb')
    output.write(json.dumps(strings, output, ensure_ascii=False, indent=3).encode('utf-8'))
    output.close()

    print('Created %s' % JSON_NAME)


def create_bin():
    strings = json.loads(open(JSON_NAME, 'rb').read(), encoding='utf-8')
    output = open(BIN_NAME, 'wb')

    count = struct.pack('<H', len(strings))
    padding = struct.pack('%dH' % len(strings), *((0,) * len(strings)))

    position = 0

    output.write(count)
    position += len(count)

    output.write(padding)
    position += len(padding)

    for idx in range(len(strings)):
        output.seek(2 + (idx * 2))

        offset_position = position
        if strings[idx] is None or len(strings[idx]) == 0:
            offset_position = 0xFFFF
        offset = struct.pack('<H', offset_position)

        output.write(offset)
        output.seek(position)

        if offset_position != 0xFFFF:
            data = strings[idx]

            search = re.search('\{(col1|ruby|reset)\}', data)
            cmd_start = -1
            if search is not None:
                cmd_start = search.start()

            while cmd_start >= 0:
                chunk = data[:cmd_start]
                chunk = chunk.encode('utf-16-le')
                output.write(struct.pack('<%ds' % len(chunk), chunk))
                position += len(chunk)

                cmd_end = data.find('}', cmd_start) + 1
                cmd = data[cmd_start:cmd_end].strip('{}')

                output.write(struct.pack('H', 0x0B))
                position += 2
                if cmd != 'reset':
                    output.write(struct.pack('<%ds' % len(cmd), cmd.encode('ascii')))
                    position += len(cmd)

                data = data[cmd_end:]
                search = re.search('\{(col1|ruby|reset)\}', data)
                if search is not None:
                    cmd_start = search.start()
                else:
                    cmd_start = -1

            data = data.encode('utf-16-le')
            output.write(struct.pack('<%ds' % len(data), data))
            position += len(data)

            output.write(struct.pack('H', 0))
            position += 2

    output.close()

    print('Created %s' % BIN_NAME)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extracts/Creates systemtext.bin')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-x', '--extract', help='Extract systemtext.bin to systemtext.json', action='store_true')
    group.add_argument('-c', '--create', help='Creates systemtext.bin from systemtext.json', action='store_true')
    args = parser.parse_args()

    if args.extract:
        extract_bin()
    elif args.create:
        create_bin()
