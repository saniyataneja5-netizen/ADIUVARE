import inspect
from abc import ABC, abstractmethod

from ..core.models import RequestContext, SignalResult


class SoftSignal(ABC):
    name: str = "unnamed"
    weight: float = 0.10

    @abstractmethod
    async def extract(self, ctx: RequestContext) -> SignalResult:
        ...


class HardSignal(ABC):
    name: str = "unnamed"
    action: str = "block"

    @abstractmethod
    def check(self, ctx: RequestContext) -> bool:
        ...


class AdiuvareStartupError(Exception):
    pass


def validate_hard_signal(sig: HardSignal) -> None:
    if inspect.iscoroutinefunction(sig.check):
        raise AdiuvareStartupError(
            f"{type(sig).__name__}.check() must stay sync in track a"
        )
