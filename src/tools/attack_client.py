"""MITRE ATT&CK TAXII / STIX client — fetches techniques and tactics."""

from __future__ import annotations

from typing import Any

import structlog

from src.models import ATTACKTechnique, ThreatSource
from src.tools.base_client import BaseAPIClient

logger = structlog.get_logger(__name__)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


class MITREATTACKClient(BaseAPIClient):
    base_url = "https://raw.githubusercontent.com"
    calls_per_second = 5.0

    _cache: dict[str, ATTACKTechnique] = {}

    async def fetch_techniques(
        self,
        tactic_filter: str | None = None,
        platform_filter: str | None = None,
    ) -> list[ATTACKTechnique]:
        """Fetch enterprise ATT&CK techniques, optionally filtered."""
        if not self._cache:
            await self._load_stix()

        techniques = list(self._cache.values())

        if tactic_filter:
            techniques = [t for t in techniques if tactic_filter.lower() in t.tactic.lower()]
        if platform_filter:
            techniques = [
                t
                for t in techniques
                if any(platform_filter.lower() in p.lower() for p in t.platforms)
            ]

        return techniques

    async def fetch_technique_by_id(self, technique_id: str) -> ATTACKTechnique | None:
        if not self._cache:
            await self._load_stix()
        return self._cache.get(technique_id)

    async def fetch_techniques_for_cve(self, cve_id: str) -> list[ATTACKTechnique]:
        """Best-effort mapping: search technique descriptions for CVE reference."""
        if not self._cache:
            await self._load_stix()
        return [t for t in self._cache.values() if cve_id in t.description]

    async def _load_stix(self) -> None:
        logger.info("loading_attack_stix", url=ATTACK_STIX_URL)
        data = await self.get("/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        objects: list[dict[str, Any]] = data.get("objects", [])

        # Build tactic lookup
        tactic_map: dict[str, str] = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                short = obj.get("x_mitre_shortname", "")
                name = obj.get("name", "")
                tactic_map[short] = name

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            ext = obj.get("external_references", [])
            technique_id = next(
                (r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"),
                None,
            )
            if not technique_id:
                continue

            url = next(
                (r.get("url", "") for r in ext if r.get("source_name") == "mitre-attack"),
                "",
            )

            kill_chain = obj.get("kill_chain_phases", [])
            tactic = next(
                (
                    tactic_map.get(kc["phase_name"], kc["phase_name"])
                    for kc in kill_chain
                    if kc.get("kill_chain_name") == "mitre-attack"
                ),
                "unknown",
            )

            mitigations = [
                r.get("description", "") for r in obj.get("x_mitre_defenses_bypassed", [])
            ]
            data_sources = obj.get("x_mitre_data_sources", [])

            self._cache[technique_id] = ATTACKTechnique(
                technique_id=technique_id,
                name=obj.get("name", ""),
                tactic=tactic,
                description=obj.get("description", "")[:500],
                platforms=obj.get("x_mitre_platforms", []),
                data_sources=data_sources[:5],
                mitigations=mitigations[:3],
                url=url,
                source=ThreatSource.MITRE_ATTACK,
            )

        logger.info("attack_stix_loaded", techniques=len(self._cache))
