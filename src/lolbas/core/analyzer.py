#!/usr/bin/env python
"""
Summary: Analyzer section to parse and digest json.

Description: Analyzer class allows us to ingest the
contents from the base64 encoded json file. From
here we can also make relations to the lolabs bins
yaml files and return content which is meaningful
to the main file for pretty printing.
"""

# Standard Python Libraries
import base64

# Third-Party Libraries
from yaml import safe_load

from .binaries import refs


class Analyzer:
    """Analyzer to create relations from JSON to yaml."""

    def __init__(self, target: str) -> None:
        """Import our file and assign other vars."""
        # Set filename
        self.file: str = target

        # Get file contents then convert to dict
        data: bytes = base64.b64decode(open(self.file, "rb").read())
        self.data: dict = safe_load(data.replace(b"\x00", b""))

        # Trying to be nice to ram so we wont load ALL the yml into memory
        self.findings: dict = {
            "Binaries": [],
            "OtherMSBinaries": [],
            "Libraries": [],
            "Scripts": [],
            "count": 0,
        }
        # self.yml_find: list = []

    def run(self) -> None:
        """Begin the analysis using content loaded in __init__."""
        # Define our list of found objects
        seen_names: list = []

        # Iterate over the refs for the correct binary
        # Define expanded path
        expanded: list = []
        for fnd in self.data.keys():
            for key in refs.keys():
                for obj in refs[key]:  # type: ignore
                    try:
                        expanded = [i["Path"].upper() for i in obj["Full_Path"]]
                    except Exception:
                        expanded = []
                    # captured path should already be upper but jic.
                    if fnd.upper() not in expanded:
                        continue
                    # Oh! We found it, lets parse it out
                    if obj["Name"] not in seen_names:
                        self.findings[key].append(obj)
                        seen_names.append(obj["Name"])
                        self.findings["count"] += 1
