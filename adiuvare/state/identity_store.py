import time
from dataclasses import dataclass

from cachetools import TTLCache


@dataclass
class IdentityWindow:
    seen: int = 0
    score_ewma: float = 0.0
    blocked_until: float = 0.0


class IdentityStore:
    def __init__(self, ttl: int = 300, block_ttl: int = 60) -> None:
        self._block_ttl = block_ttl
        self._windows: TTLCache[str, IdentityWindow] = TTLCache(maxsize=10000, ttl=ttl)

    def get(self, identity: str) -> IdentityWindow:
        win = self._windows.get(identity)
        if win is None:
            win = IdentityWindow()
            self._windows[identity] = win
        return win

    def update(self, identity: str, win: IdentityWindow) -> None:
        self._windows[identity] = win

    def set_blocked(self, identity: str, seconds: int | float | None = None) -> None:
        win = self.get(identity)
        win.blocked_until = time.time() + (seconds or self._block_ttl)
        self.update(identity, win)

    def block(self, identity: str) -> None:
        self.set_blocked(identity)

    def clear_block(self, identity: str) -> None:
        win = self.get(identity)
        win.blocked_until = 0.0
        self.update(identity, win)

    def unblock(self, identity: str) -> None:
        self.clear_block(identity)

    def is_blocked(self, identity: str) -> bool:
        win = self._windows.get(identity)
        if win is None:
            return False

        if win.blocked_until <= time.time():
            win.blocked_until = 0.0
            self.update(identity, win)
            return False

        return True

    def bump(self, identity: str) -> int:
        win = self.get(identity)
        win.seen += 1
        self.update(identity, win)
        return win.seen
