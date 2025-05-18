from abc import ABC, abstractmethod

class ScraperPlugin(ABC):
    @abstractmethod
    def supports(self, ta: str) -> bool:
        """Return True if this plugin can handle the given TA."""
        pass

    @abstractmethod
    def scrape_victims(self, **kwargs):
        """Scrape victim data for the given TA."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    def supported_tas(self):
        """Optionally, return a list of TAs this plugin supports."""
        return [] 