import os
from collections import deque


class UnixSocketEventStream:
    def __init__(self, name: str = "adiuvare") -> None:
        self.name = name
        self.path = os.path.join(os.getenv("TEMP", "/tmp"), f"{name}.sock")
        self._recent = deque(maxlen=100)

    async def emit(self, event) -> None:
        self._recent.append(event)

    def recent(self) -> list:
        return list(self._recent)
