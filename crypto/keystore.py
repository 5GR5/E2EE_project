import json
from pathlib import Path
from typing import Any, Dict

class JsonKeyStore:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            self.path.write_text(json.dumps({"devices": {}}, indent=2), encoding="utf-8")

    def load(self) -> Dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, data: Dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_device(self, device_id: str) -> Dict[str, Any] | None:
        data = self.load()
        return data["devices"].get(device_id)

    def put_device(self, device_id: str, device_blob: Dict[str, Any]) -> None:
        data = self.load()
        data["devices"][device_id] = device_blob
        self.save(data)
