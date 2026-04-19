class WhitelistStore:
    def __init__(self) -> None:
        self._ids: set[str] = set()
        self._banned_ips: set[str] = set()

    def add(self, identity: str) -> None:
        self._ids.add(identity)

    def allows(self, identity: str) -> bool:
        return identity in self._ids

    def ban_ip(self, ip: str) -> None:
        self._banned_ips.add(ip)

    def ip_blocked(self, ip: str) -> bool:
        return ip in self._banned_ips
