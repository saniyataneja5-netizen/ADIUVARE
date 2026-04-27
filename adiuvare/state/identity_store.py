import time
import threading
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
        self._lock = threading.RLock()

    def get(self, identity: str) -> IdentityWindow:
        with self._lock:
            win = self._windows.get(identity)
            if win is None:
                win = IdentityWindow()
                self._windows[identity] = win
            return win

    def update(self, identity: str, win: IdentityWindow) -> None:
        with self._lock:
            self._windows[identity] = win

    def items(self) -> list[tuple[str, IdentityWindow]]:
        with self._lock:
            return list(self._windows.items())

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
        with self._lock:
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

    def apply_score(self, identity: str, score: float, alpha: float = 0.35) -> IdentityWindow:
        win = self.get(identity)
        if win.score_ewma == 0.0:
            win.score_ewma = score
        else:
            win.score_ewma = (win.score_ewma * (1 - alpha)) + (score * alpha)
        self.update(identity, win)
        return win


class ThreadSafeIdentityStore(IdentityStore):
    def __init__(self, ttl: int = 300, block_ttl: int = 60) -> None:
        super().__init__(ttl=ttl, block_ttl=block_ttl)
        self._thread = threading.RLock()

    def get(self, identity: str) -> IdentityWindow:
        with self._thread:
            return super().get(identity)

    def update(self, identity: str, win: IdentityWindow) -> None:
        with self._thread:
            super().update(identity, win)

    def set_blocked(self, identity: str, seconds: int | float | None = None) -> None:
        with self._thread:
            super().set_blocked(identity, seconds)

    def clear_block(self, identity: str) -> None:
        with self._thread:
            super().clear_block(identity)

    def is_blocked(self, identity: str) -> bool:
        with self._thread:
            return super().is_blocked(identity)

    def bump(self, identity: str) -> int:
        with self._thread:
            return super().bump(identity)

    def apply_score(self, identity: str, score: float, alpha: float = 0.35) -> IdentityWindow:
        with self._thread:
            return super().apply_score(identity, score, alpha)
