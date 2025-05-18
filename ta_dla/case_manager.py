"""Case directory and configuration management for TA-DLA."""
import os
import json
from typing import Optional, Dict

class CaseManager:
    def __init__(self, case_dir: str):
        self.case_dir = case_dir
        # TODO: Validate and create directory structure as needed

    def ensure_structure(self):
        """
        Ensure all required subdirectories and files exist for a TA-DLA case.
        Creates: downloads/, extracted/, reports/, logs/
        """
        os.makedirs(self.case_dir, exist_ok=True)
        for sub in ['downloads', 'extracted', 'reports', 'logs']:
            os.makedirs(os.path.join(self.case_dir, sub), exist_ok=True)

    def load_config(self) -> Optional[Dict]:
        """
        Load case.json for this case (metadata/config).
        Returns dict or None if not found.
        """
        config_path = os.path.join(self.case_dir, 'case.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return None

    def save_config(self, config: Dict):
        """
        Save case.json for this case.
        """
        config_path = os.path.join(self.case_dir, 'case.json')
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

    def load_metadata(self) -> Dict:
        """
        Load per-case metadata from metadata.json (legacy).
        """
        meta_path = os.path.join(self.case_dir, 'metadata.json')
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                return json.load(f)
        return {}

    def save_metadata(self, metadata: Dict):
        """
        Save per-case metadata to metadata.json (legacy).
        """
        meta_path = os.path.join(self.case_dir, 'metadata.json')
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2)

    @staticmethod
    def prompt_for_case_metadata(enrichment_client=None) -> Dict:
        """
        Prompt the analyst for all required case metadata, using ransomware.live if available.
        Returns a dict with victim, ta_group, description, analyst, date, etc.
        Handles ransomware.live API errors gracefully and allows manual entry.
        """
        import datetime
        import click
        metadata = {}
        # Victim
        victim = None
        try:
            if enrichment_client:
                recent_victims = enrichment_client.get_recent_victims() or []
                victim_names = [v['victim'] for v in recent_victims if 'victim' in v]
                click.echo("Recent victims from ransomware.live:")
                click.echo(", ".join(sorted(victim_names)[:30]) + (", ..." if len(victim_names) > 30 else ""))
                victim = click.prompt('Enter victim/organization name (or "unknown")', default='unknown')
                matched_victim = None
                if victim and victim.lower() != 'unknown':
                    for v in recent_victims:
                        if victim.lower() == v['victim'].lower():
                            matched_victim = v
                            break
                    if not matched_victim:
                        for v in recent_victims:
                            if victim.lower() in v['victim'].lower():
                                matched_victim = v
                                break
                    if matched_victim:
                        metadata['victim'] = matched_victim
                    else:
                        click.echo(f"Victim '{victim}' not found in recent ransomware.live data. Proceeding as manual entry.")
                        metadata['victim'] = {'name': victim}
                else:
                    metadata['victim'] = {'name': victim}
            else:
                raise Exception('No enrichment client')
        except Exception:
            click.echo("[WARNING] Could not fetch recent victims from ransomware.live. Enter victim manually.")
            victim = click.prompt('Enter victim/organization name (or "unknown")', default='unknown')
            metadata['victim'] = {'name': victim}
        # Threat Actor
        ta_group = None
        try:
            if enrichment_client:
                groups = enrichment_client.get_groups() or []
                group_names = [g['name'] for g in groups if 'name' in g]
                click.echo("Known Threat Actor groups from ransomware.live:")
                click.echo(", ".join(sorted(group_names)))
                ta_group = click.prompt('Enter Threat Actor group name (or "unknown")', default='unknown')
                matched_group = None
                if ta_group and ta_group.lower() != 'unknown':
                    for g in groups:
                        if ta_group.lower() == g['name'].lower():
                            matched_group = g['name']
                            break
                    if not matched_group:
                        for g in groups:
                            if ta_group.lower() in g['name'].lower():
                                matched_group = g['name']
                                break
                    if matched_group:
                        metadata['ta_group'] = matched_group
                    else:
                        click.echo(f"Group '{ta_group}' not found in ransomware.live. Proceeding as manual entry.")
                        metadata['ta_group'] = ta_group
                else:
                    metadata['ta_group'] = ta_group
            else:
                raise Exception('No enrichment client')
        except Exception:
            click.echo("[WARNING] Could not fetch TA groups from ransomware.live. Enter group manually.")
            ta_group = click.prompt('Enter Threat Actor group name (or "unknown")', default='unknown')
            metadata['ta_group'] = ta_group
        # Case description
        metadata['description'] = click.prompt('Enter a brief case description', default='')
        # Analyst
        metadata['analyst'] = click.prompt('Enter your name or analyst ID', default='')
        # Date
        metadata['date'] = datetime.datetime.now().isoformat()
        return metadata 