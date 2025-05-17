#!/usr/bin/env python3
"""
Fetch and print all ransomware groups (TAs) active in the last 6 months using ransomware.live API.
"""
from ta_dla.utils import get_active_ransomware_groups_last_6_months

def main():
    groups = get_active_ransomware_groups_last_6_months()
    print("Active ransomware groups (last 6 months):")
    for group in groups:
        print(f"- {group}")

if __name__ == "__main__":
    main() 