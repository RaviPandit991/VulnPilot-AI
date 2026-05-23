"""Service / banner normalization."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectedService:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: Optional[str] = None       # e.g. ssh, http, smb
    product: Optional[str] = None    # e.g. OpenSSH, Apache httpd
    version: Optional[str] = None    # e.g. 8.2p1
    extrainfo: Optional[str] = None
    banner: Optional[str] = None
    cpe: list[str] = field(default_factory=list)

    @property
    def vendor_product(self) -> tuple[str | None, str | None]:
        """Best-effort vendor/product extraction from CPE or product fields."""
        for entry in self.cpe:
            # cpe:/a:vendor:product:version
            parts = entry.replace("cpe:/", "").replace("cpe:2.3:", "").split(":")
            if len(parts) >= 3:
                return parts[1].lower(), parts[2].lower()
        if self.product:
            return None, self.product.lower().split()[0]
        if self.name:
            return None, self.name.lower()
        return None, None
