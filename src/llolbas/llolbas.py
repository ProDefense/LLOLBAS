#!/usr/bin/env python
"""llolbas is a local server and digester for LOLBAS.

llolbas is a command line program which allows a user
to not only run a local instance of the hit internet
resource LOLBAS, but also be able to digest output
from the included ingestor to allow for curated listing
of binaries which exist within a target Windows
computer.

EXIT STATUS
    This utility exits with one of the following values:
    0   Execution completed successfully.
    >0  An error occurred.

Usage:
  llolbas serve [options]
  llolbas serve (-p PORT | --port=PORT)
  llolbas serve (-d FILE | --digest=FILE)
  llolbas (-h | --help)

Options:
    -h --help                   Show this message.
    -d FILE --digest=FILE       If specified, use file
                                from one of the ingestors to
                                curate the LOLBAS served
                                output.
    -p PORT --port=PORT         Specify the port to start
                                the flask server on. [default: 5000].
"""

# Standard Python Libraries
import os
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
from flask import Flask, render_template
from schema import And, Or, Schema, SchemaError, Use

from ._version import __version__

# Internal Libraries
from .core import Analyzer, functions

# Debug, if you're cool
DEBUG = False


def run_server(digt: str, port: int = 5000):
    """Serve up the findings on a static website."""
    app = Flask(__name__)

    # Run analyzer on digest. If digest is none,
    # then the known binaries will be all of those
    # known by LOLBAS.
    a = Analyzer(digt)
    a.run()

    # Including this so I can do a loop in functions ( function_list.html:9 )
    app.jinja_options["extensions"] = []
    app.jinja_options["extensions"].append("jinja2.ext.do")

    # Attribute needed for jinja template usages
    findings = a.findings

    @app.route("/")
    @app.route("/home")
    def home():
        return render_template("bin_table.html", data=findings, func=functions)

    @app.route("/about")
    def about():
        return render_template("about.html", title="About")

    # Be quirky and use the name of binary as page name.
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

    app.run(debug=DEBUG, port=port)


def main() -> int:
    """Take in nothing, return int."""
    # Obtain args from docopt
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    # Validate and convert args as needed with schema
    schema: Schema = Schema(
        {
            "--port": Or(
                None,
                And(
                    Use(int),
                    lambda p: 1 < p < 65535,
                    error="Port specified must be between 1 and 65535.",
                ),
            ),
            "--digest": Or(
                None,
                And(
                    str,
                    lambda filename: os.path.isfile(filename),
                    error=f'Input file {str(args["--digest"])} does not exist!',
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

    # Set local parameters
    PORT = validated_args["--port"]
    DIGT = validated_args["--digest"]

    # Time to parse and serve
    run_server(DIGT, PORT)

    # Return success after ending
    """
    Realistically we probably will never reach
    here because of how Flask works
    """
    return 0
