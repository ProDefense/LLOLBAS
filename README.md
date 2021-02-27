# LOLBAS

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![forthebadge](https://forthebadge.com/images/badges/contains-tasty-spaghetti-code.svg)](https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.thewholesomedish.com%2Fspaghetti%2F&psig=AOvVaw3OneeN_AB3XxZzgCPPTtfv&ust=1614550372646000&source=images&cd=vfe&ved=0CAIQjRxqFwoTCJjQwf2Ki-8CFQAAAAAdAAAAABAD)
[![forthebadge](https://forthebadge.com/images/badges/it-works-why.svg)](https://www.youtube.com/watch?v=kyti25ol438)

[![GitHub Build Status](https://github.com/MattKeeley/LOBAS/workflows/build/badge.svg)](https://github.com/MattKeeley/LOBAS/actions)

`LOBAS` is a repo containing injestors and a parser which in conjunction with
one another will allow for indexing of all potential binaries, scripts, and
libraries which exist on target Windows system. These findings can then be cross
referenced with the intent of the user; whether the intent is to execute
commands, download files, or even upload files, this tool will help you find
the right file to do so! This was inspired by [LOLBAS](https://lolbas-project.github.io).

`LOBAS` is a local implementation of the popular LOLBAS (Living off the Land
with Binaries and Scripts). The idea is to allow a user to use LOLBAS locally
and with a curated list of applications from what files exist on a target
system. The program then will host this local instance of LOLBAS locally using
flask to allow further inspection of each file the program saw.

## Getting Started

`LOBAS` requires **Python 3.6+**. Python 2 is not supported.

`LOBAS` can be installed as a module using `pip` and the requirements.txt file
in the repository or by directly calling upon the git repo using the git
modifier for pip.

### Installed as a Module

`LOBAS` Using pip and requirements.txt

```console
pip install --requirement requirements.txt
```

`LOBAS` Using pip and git url

```console
pip install git+https://github.com/MattKeeley/LOBAS.git
```

The digester can then be ran directly

```console
digestlol -h
digestlol output.lol
```

### Standalone Usage and Examples

```console
digestLOL is a digestor for any ingestor for LOLABS.

digestLOL is designed to allow any user who uses one of the
ingestors for LOLABS to bring in the base64 encoded JSON and
digest it into this here program. The expected output is
potential vectors of attack for Windows Systems.

EXIT STATUS
    This utility exits with one of the following values:
    0   Execution completed successfully.
    >0  An error occurred.

Usage:
  digestLOL <file>
  digestLOL (-h | --help)

Options:
    -h --help                   Show this message.
```

#### Options

```console
<file>: This is the file which will be digested by the digester.
```

#### Sample Output

The ingestor scripts should have no output. Debug mode can be turned on however,
if you wish to have some sort of verbosity. The output from these should be a
large base64 encoded JSON formatted string.

Once the digester is ran, we see the output from flask shown like so:

```console
 * Serving Flask app "lolbas.digestlol" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
```

Browsing to the website you are met with the following screen: <br>
<img src="/resources/images/landing.png" alt="landing.png" style="zoom:25%;" />

Clicking on an application you find will look like the following: <br>
<img src="/resources/images/application.png" alt="application.png" style="zoom:25%;" />

## Disclaimer

> This tool is only for testing and academic purposes and can only be used where
> strict consent has been given. Do not use it for illegal purposes! It is the
> end user’s responsibility to obey all applicable local, state and federal laws.
> Developers assume no liability and are not responsible for any misuse or damage
> caused by this tool and software.

## Credit

The credit for all the LOLBAS content goes to the
[LOLBAS-Project](https://github.com/LOLBAS-Project).

## Contributing

We welcome contributions! Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE)
file for details
