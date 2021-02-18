# LOBAS

[![made-with-python](http://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)

This is a standalone script written in Python 3 for [LOLBAS](https://lolbas-project.github.io/).
You can search for windows executables that can be exploited to bypass system security restrictions.
These binaries can be abused to break out of restricted shells, escalate privileges, transfer files, spawn bind and reverse shells, etc...

The functions are from [https://lolbas-project.github.io/](https://lolbas-project.github.io/) and all credit goes to its respective contributors.
They are simplified (no need for environmental variables) and syntax highlighted.

## Download

```
git clone https://github.com/MattKeeley/LOBAS
```

## Install

The script has 2 dependencies:

*   [colorama](https://pypi.org/project/colorama/)
*   [pygments](https://pypi.org/project/Pygments/)

You can install these by typing:

```
python3 setup.py install
```

## Run

```
python3 lolbas.py [binary]
```

## Screenshots


Screenshot 1             |  Screenshot 2
:-----------------------:|:-----------------------:
![Screenshot1](https://i.imgur.com/1EzFiGQ.png)  |  ![Screenshot2](https://i.imgur.com/icgmDct.png)


### Disclaimer

> This tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this tool and software.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details
