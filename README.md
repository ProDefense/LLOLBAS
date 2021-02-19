# LOBAS

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com) 
[![forthebadge](https://forthebadge.com/images/badges/contains-17-coffee-cups.svg)](https://forthebadge.com) 
[![forthebadge](https://forthebadge.com/images/badges/contains-tasty-spaghetti-code.svg)](https://forthebadge.com) 
[![forthebadge](https://forthebadge.com/images/badges/it-works-why.svg)](https://forthebadge.com)

This is a Python program which is created to help digest information from a
Windows system and compare it against the database known as
[LOLBAS](https://lolbas-project.github.io). With a given digestor (the
powershell one is in this repo), download the base64 encoded JSON created by the
digestor and ingest it using the Python program digestLOL.py. The goal is to
help an operator, pentester, or general security analyst realize potential
executables or scripts which could be exploited to bypass system security
restrictions. These binaries can be abused to break out of restricted shells,
escalate privileges, transfer files, spawn bind and reverse shells, etc...

The credit for all the LOLBAS content goes to the
[LOLBAS-Project](https://github.com/LOLBAS-Project).

## Download

```
git clone https://github.com/MattKeeley/LOBAS
```

## Run
On the target machine, run the included Powershell script like so:
```powershell
Powershell.exe .\powerlolbas.ps1
```
This script has the following parameters which can be modified:
```
- OUTPUT to stdout.
- CWD can be changed to a desired dir.
- OUTFILE can be changed to desired output name.
```
Then once the output file is downloaded back to the attacking machine, you can
digest the file with digestLOL.py like so:
```bash
python3 ./outfile.lol -l ./path/to/LOLBAS-repo
```

### Disclaimer

> This tool is only for testing and academic purposes and can only be used where 
> strict consent has been given. Do not use it for illegal purposes! It is the 
> end user’s responsibility to obey all applicable local, state and federal laws. 
> Developers assume no liability and are not responsible for any misuse or damage 
> caused by this tool and software.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details
