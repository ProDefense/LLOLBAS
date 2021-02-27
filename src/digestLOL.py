#!/usr/bin/env python
"""digestLOL is a digestor for any ingestor for LOLABS

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
    -l LOLBAS --lolloc LOLBAS   Define the location for
                                lolbas. [default: ./LOLBAS]
"""

# Standard Python Libraries
import os
from typing import Any, Dict

# Third-Party Libraries
import docopt
from schema import And, Or, Schema, SchemaError, Use
from flask import Flask, render_template, url_for

# Internal Libraries
from core import analyzer
__version__ = "0.1" # This is normally an internal import
DEBUG = False

def parse_n_serve(output, lolabsloc):
    '''Serve up the findings on a static website.'''
    app = Flask(__name__)

    a = analyzer.Analyzer(output, lolabsloc)
    a.run()

    # Including this so I can do a loop in functions ( function_list.html:9 )
    app.jinja_options['extensions'].append('jinja2.ext.do')

    # Attribute needed for jinja template usages
    loc = a.lolabs + "/"
    #print(f"LOCATION: {loc}")
    data = a.findings
    #print(f"DATA: {data}")
    ymlfiles = a.yml_find
    #print(f"YML FILES: {ymlfiles}")

    # Dict of functions for pretty listing
    functions = {
        "ads": "Alternate data streams",
        "execute": "Execute",
        "reconnaissance": "Recon",
        "uac bypass": "UAC Bypass",
        "upload": "Upload",
        "download": "Download",
        "dump": "Dump",
        "credentials": "Creds",
        "copy": "Copy",
        "compile": "Compile",
        "awl bypass": "AWL Bypass",
        "encode": "Encode",
        "decode": "Decode"
    }

    # Fix some.... discrepancies... cough....
    names = {}
    for ym in data:
        names[ym['Name'].lower()] = ym['Name']
        names['.'.join(ym['Name'].lower().split(".")[:-1])] = ym['Name']
    for val in data:
        for j in val['Commands']:
            try:
                j['OperatingSystem']
            except:
                j['OperatingSystem'] = "Not specified"

    @app.route("/")
    @app.route("/home")
    def home():
        return render_template('bin_table.html', files=ymlfiles, bin=data, location=loc, count=len(data), func=functions, nm=names)

    @app.route("/about")
    def about():
        return render_template('about.html', title='About')

    @app.route("/<command>")
    def cmd(command):
        # Run through the yml file and check names then serve that one
        page = None
        for p in data:
            if command.lower() == p['Name'].lower().split(".")[0]:
                page = p
        return render_template('bin.html', page=page, cmd=command)

    app.run(debug=DEBUG)

def main() -> int:
    '''Main for entry program, take in filename.'''
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
            "--lolloc": Or(
                None,
                And(
                    str,
                    lambda filename: os.path.isdir(filename),
                    error=f"LOLBAS Dir not found! {str(args['--lolloc'])}",
                ),
            ),
            str: object, # Dont care about other keys if any
        }
    )
    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the args was invalid
        print(err, file=sys.stderr)
        return 1

    # Time to parse and serve
    parse_n_serve(validated_args['<file>'], validated_args['--lolloc'])

if __name__ == "__main__":
    main()

