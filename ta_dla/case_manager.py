"""Case directory and configuration management for TA-DLA."""
import os
import json

class CaseManager:
    def __init__(self, case_dir):
        self.case_dir = case_dir
        # TODO: Validate and create directory structure as needed

    def ensure_structure(self):
        """Ensure all required subdirectories and files exist."""
        # TODO: Implement directory creation logic
        pass

    def load_config(self):
        """Load ta_config.json for this case."""
        # TODO: Implement config loading
        pass

    def save_config(self, config):
        """Save ta_config.json for this case."""
        # TODO: Implement config saving
        pass

    def load_metadata(self):
        """Load per-case metadata from metadata.json."""
        meta_path = os.path.join(self.case_dir, 'metadata.json')
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                return json.load(f)
        return {}

    def save_metadata(self, metadata):
        """Save per-case metadata to metadata.json."""
        meta_path = os.path.join(self.case_dir, 'metadata.json')
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2) 