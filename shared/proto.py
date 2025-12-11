import json

def control_msg(msg_type: str, payload: dict) -> bytes:
    return json.dumps({"type": msg_type, "payload": payload}).encode()

def parse_control_msg(data: bytes):
    obj = json.loads(data.decode())
    return obj.get("type"), obj.get("payload", {})
