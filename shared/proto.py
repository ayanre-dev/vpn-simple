import json

def control_msg(msg_type: str, payload: dict) -> bytes:
    return json.dumps({"type": msg_type, "payload": payload}).encode()

def parse_control_msg(data: bytes):
    obj = json.loads(data.decode())
    return obj.get("type"), obj.get("payload", {})

# TCP opcodes
TCP_INIT = 0
TCP_READY = 1
TCP_DATA = 2
TCP_CLOSE = 3
TCP_ERR = 4
