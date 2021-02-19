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

# Internal Libraries
from core import analyzer
__version__ = "0.1" # This is normally an internal import

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

    # At this point, we know it exists, lets parse!!
    an = analyzer.Analyzer(validated_args['<file>'], validated_args['--lolloc'])
    an.run()
    an.pretty_print()

if __name__ == "__main__":
    main()

