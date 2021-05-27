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

# Internal Libraries
from .binaries import refs


class Analyzer:
    """Analyzer to create relations from JSON to yaml."""

    def __init__(self, target: str) -> None:
        """Analyze the ingested pool if there is one."""
        # If file name is actually existing, set it for import
        if target:  # If not None
            self.file = target

            # Get file contents then convert to dict
            with open(self.file, "rb") as fp:
                file_data: bytes = fp.read()
            decoded_data: bytes = base64.b64decode(file_data)
            self.binary_listings: dict = safe_load(decoded_data.replace(b"\x00", b""))
        else:
            self.file = ""  # None defined, so we load everything

        # Our stored dict of attributes we curate
        self.findings: dict = {
            "Binaries": [],
            "OtherMSBinaries": [],
            "Libraries": [],
            "Scripts": [],
            "count": 0,
        }

    def run(self) -> int:
        """Begin the analysis using content loaded in __init__."""
        # Define our list of found objects
        seen_names: list = []

        # Iterate over the refs for the correct binary
        # Define expanded path
        expanded: list = []

        # If filename is None, then just read in all the values
        if self.file == "":
            for categ in refs.keys():
                for prog in refs[categ]:  # type: ignore
                    try:
                        expanded = [i["Path"].upper() for i in prog["Full_Path"]]
                    except Exception:
                        expanded = []
                    # Oh! We found it, lets parse it out
                    if prog["Name"] not in seen_names:
                        self.findings[categ].append(prog)
                        seen_names.append(prog["Name"])
                        self.findings["count"] += 1
        else:
            for fnd in self.binary_listings.keys():
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
        return 0
