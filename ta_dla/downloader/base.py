from abc import ABC, abstractmethod

class DownloaderPlugin(ABC):
    @abstractmethod
    def supports(self, ta: str, url: str) -> bool:
        """Return True if this plugin can handle the given TA and/or URL."""
        pass

    @abstractmethod
    def download(self, url: str, dest: str, **kwargs):
        """Download the file to dest."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    def supported_tas(self):
        """Optionally, return a list of TAs this plugin supports."""
        return [] 