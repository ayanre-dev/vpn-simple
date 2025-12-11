import struct

def encode_frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload

def decode_frames(buf: bytearray):
    frames = []
    offset = 0
    while len(buf) - offset >= 4:
        (length,) = struct.unpack_from("!I", buf, offset)
        if len(buf) - offset - 4 < length:
            break
        start = offset + 4
        end = start + length
        frames.append(bytes(buf[start:end]))
        offset = end
    if offset:
        del buf[:offset]
    return frames
