import requests
import logging
from typing import Optional, Dict, Any, List

BASE_URL = "https://api.ransomware.live/v2"

class RansomwareLiveEnrichment:
    """
    Standalone enrichment client for ransomware.live API.
    Fetches and caches group, victim, CERT, and YARA info.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("ransomware_live_enrichment")
        self.cache: Dict[str, Any] = {}

    def _get(self, endpoint: str) -> Any:
        url = f"{BASE_URL}{endpoint}"
        if url in self.cache:
            return self.cache[url]
        try:
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                # Try JSON, fallback to text
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                self.cache[url] = data
                return data
            else:
                self.logger.warning(f"API error {resp.status_code} for {url}")
                return None
        except Exception as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return None

    def get_group(self, group_name: str) -> Optional[Dict]:
        """Fetch group details by name."""
        return self._get(f"/group/{group_name}")

    def get_groups(self) -> Optional[List[Dict]]:
        """Fetch all ransomware groups."""
        return self._get("/groups")

    def get_recent_victims(self) -> Optional[List[Dict]]:
        """Fetch recent victims."""
        return self._get("/recentvictims")

    def search_victims(self, keyword: str) -> Optional[List[Dict]]:
        """Search for victims by keyword."""
        return self._get(f"/searchvictims/{keyword}")

    def get_cert_contacts(self, country_code: str) -> Optional[List[Dict]]:
        """Fetch CERT/CSIRT contacts for a country (ISO2 code)."""
        return self._get(f"/certs/{country_code}")

    def get_yara_rules(self, group_name: str) -> Optional[str]:
        """Fetch YARA rules for a group as plain text (may be None or error HTML)."""
        return self._get(f"/yara/{group_name}")

    def get_group_victims(self, group_name: str) -> Optional[List[Dict]]:
        """Fetch all victims claimed by a group."""
        return self._get(f"/groupvictims/{group_name}")

    def get_victim_by_month(self, year: int, month: int) -> Optional[List[Dict]]:
        """Fetch victims by year and month."""
        return self._get(f"/victims/{year}/{month:02d}")

# Example usage:
# enrichment = RansomwareLiveEnrichment()
# group_info = enrichment.get_group('lockbit')
# yara_rules = enrichment.get_yara_rules('akira') 