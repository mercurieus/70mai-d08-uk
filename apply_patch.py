"""Apply the Ukrainian resource patch to the verified D08 1.0.5.ww image."""
import argparse
import hashlib
import lzma
from pathlib import Path
import struct

STOCK_SHA256 = '51138cff14af43916ea9d1e828d8c4a5e4534e7b5f3d21af15857cd533efc344'
RELEASE_SHA256 = '3874fdedb9d88ee61eb45184f803c8571da5eb752d8eceebbc803492055ab09a'
PATCH = Path(__file__).with_name('d08-1.0.5ww-uk.patch.xz')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stock', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    image = bytearray(args.stock.read_bytes())
    if hashlib.sha256(image).hexdigest() != STOCK_SHA256:
        parser.error('Wrong stock image. Extract the original D08 1.0.5.ww FW_DR0010.bin and check SHA-256.')
    patch = lzma.decompress(PATCH.read_bytes())
    previous_end = cursor = 0
    while cursor < len(patch):
        offset, size = struct.unpack_from('<II', patch, cursor)
        cursor += 8
        if size == 0 or offset < previous_end or offset + size > len(image) or cursor + size > len(patch):
            parser.error('Invalid patch record.')
        image[offset:offset + size] = patch[cursor:cursor + size]
        previous_end = offset + size
        cursor += size
    if hashlib.sha256(image).hexdigest() != RELEASE_SHA256:
        parser.error('Output SHA-256 mismatch.')
    with args.output.open('xb') as output:
        output.write(image)
    print(f'Created {args.output} ({RELEASE_SHA256})')

if __name__ == '__main__':
    main()
