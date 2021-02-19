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
import json
import os
from glob import glob

# Third-Party Libraries
from yaml import safe_load
from rich.table import Table
from rich.console import Console


class Analyzer:
    """Analyzer to create relations from JSON to yaml."""

    def __init__(self, target: str, lolabs: str) -> None:
        """Import our file and assign other vars."""
        # Set filename
        self.file: str = target

        # Get file contents then convert to dict
        data = base64.b64decode(open(self.file, "rb").read())
        self.data: dict = safe_load(data.replace(b"\x00",b""))

        # Location of lolbas repo in this repo
        if lolabs[-1] == "\\" or lolabs[-1] == "/":
            lolabs = lolabs[:-1]
        self.lolabs = lolabs

        # Get all YML files
        # Credit: https://stackoverflow.com/questions/18394147/recursive-sub-folder-search-and-return-files-in-a-list-python
        self.ymlfiles = [y for x in os.walk(self.lolabs) for y in glob(os.path.join(x[0], '*.yml'))]

        # Trying to be nice to ram so we wont load ALL the yml into memory
        self.findings: list = []

    def run(self) -> None:
        """Begin the analysis using content loaded in __init__."""
        # Define our list of found objects
        found = []
        seen_names = []

        # Iterate over the yml files and match
        for yml in self.ymlfiles:
            # Exclude the LOLUtils for now, the format sucks
            if "LOLUtilz" in yml:
                continue
            val = open(yml,"rb").read().replace(b"---",b"").replace(b"@",b"AT_SYMBOL")
            loaded = safe_load(val)
            try:
                expanded = [i['Path'].upper() for i in loaded['Full_Path']]
            except:
                expanded = ""
            for fnd in self.data.keys():
                # Early exit if its not seen
                if fnd not in expanded:
                    continue
                # Oh! We found it, lets parse some shit
                loaded['perms'] = self.data[fnd]['Perms']
                if loaded['Name'] not in seen_names:
                    found.append(loaded)
                    seen_names.append(loaded['Name'])

        # Store the findings
        self.findings: list = found

    def pretty_print(self, mode: str = "basic") -> None:
        """Pretty print out our found results."""
        '''
        - Show header: To display some name
        - Show lines:  Allow a line between each item in table
        - I decided to put header as the name but we could do otherwise... idk??
        '''
        # List of tables n shit
        tables = []

        # Rich console object
        console = Console()

        # Start iterating over all items in findings
        for find in self.findings:
            # Define our rich table
            table = Table(show_header=True, header_style='bold #2070b2',title=f'[bold] {find["Name"]}', show_lines=True)

            # Add some collumns, rows, and spice to it
            table.add_column("Attribute",justify="left")
            table.add_column("Value",justify="center")
            table.add_row("Name",f"[green]{find['Name']}")
            table.add_row("Description",f"[green]{find['Description']}")
            table.add_row("Author",f"[green]{find['Author']}")
            table.add_row("Created",f"[green]{find['Created']}")
            fp = "\n".join([i['Path'] for i in find['Full_Path']])
            table.add_row("Full Path",f"[green]{fp}")
            try:
                cs = "\n".join([i['Code'] for i in find['Code_Sample']])
                table.add_row("Code Sample",f"[green]{cs}")
            except Exception:
                try:
                    cs = "\n".join([i['Code'] for i in find['Code Sample']])
                    table.add_row("Code Sample",f"[green]{cs}")
                except Exception:
                    pass
            try:
                ioc = "\n".join([i['IOC'] for i in find['Detection']])
                table.add_row("Detection",f"[green]{ioc}")
            except Exception:
                pass
            try:
                rec = "\n".join([i['Link'] for i in find['Resources']])
                table.add_row("Resources",f"[green]{rec}")
            except Exception:
                pass
            try:
                ack = "\n".join([f"{i['Person']} --> {i['Handle']}" for i in find['Acknowledgement']]).replace("AT_SYMBOL","@")
                table.add_row("Acknowledgement",f"[green]{ack}")
            except Exception:
                pass

            # Add the table to the list
            tables.append(table)

        # Print out all the tables
        for tbl in tables:
            console.print(tbl)



























