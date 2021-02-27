#!/usr/bin/env python
"""digestLOL is a digestor for any ingestor for LOLABS.

digestLOL is designed to allow any user who uses one of the
ingestors for LOLABS to bring in the base64 encoded JSON and
digest it into this here program. The expected output is
potential vectors of attack for Windows Systems.

EXIT STATUS
    This utility exits with one of the following values:
    0   Execution completed successfully.
    >0  An error occurred.

Usage:
  digestLOL <file> [options]
  digestLOL (-h | --help)

Options:
    -h --help                   Show this message.
"""

# Standard Python Libraries
import os
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
from flask import Flask, render_template
from schema import And, Or, Schema, SchemaError

from ._version import __version__

# Internal Libraries
from .core import Analyzer, functions

DEBUG = False


def parse_n_serve(output):
    """Serve up the findings on a static website."""
    app = Flask(__name__)

    a = Analyzer(output)
    a.run()

    # Including this so I can do a loop in functions ( function_list.html:9 )
    app.jinja_options["extensions"].append("jinja2.ext.do")

    # Attribute needed for jinja template usages
    # loc = a.lolabs + "/"
    # print(f"LOCATION: {loc}")
    findings = a.findings
    # print(f"DATA: {data}")
    # ymlfiles = a.yml_find
    # print(f"YML FILES: {ymlfiles}")

    @app.route("/")
    @app.route("/home")
    def home():
        return render_template(
            "bin_table.html", data=findings, func=functions
        )  # files=ymlfiles, bin=data, location=loc, count=len(data), func=functions)

    @app.route("/about")
    def about():
        return render_template("about.html", title="About")

    @app.route("/<command>")
    def cmd(command):
        # Run through the yml file and check names then serve that one
        page = None
        for k in findings.keys():
            if k == "count":
                continue
            for p in findings[k]:
                if command.lower() == p["pname"]:
                    page = p
        return render_template("bin.html", page=page, cmd=command)

    app.run(debug=DEBUG)


def main() -> int:
    """Take in nothing, return int."""
    # Obtain args from docopt
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    # Validate and convert args as needed with schema
    schema: Schema = Schema(
        {
            "<file>": Or(
                None,
                And(
                    str,
                    lambda filename: os.path.isfile(filename),
                    error=f"Input file: {str(args['<file>'])} does not exist!",
                ),
            ),
            str: object,  # Dont care about other keys if any
        }
    )
    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the args was invalid
        print(err, file=sys.stderr)
        return 1
    return 0

    # Time to parse and serve
    parse_n_serve(validated_args["<file>"])
