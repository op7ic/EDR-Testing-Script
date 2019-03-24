# EDR-Testing-Script

This repository contains simple script to test EDR solutions against Mitre ATT&CK/LOLBAS/Invoke-CradleCrafter frameworks. This project is very much in its infancy right now. It is written as a single batch script so it can be easily uploaded and run (as opposed to un-zipped, compiled and installed). The script can run either as a normal user or as Administrator however not giving it high privilages will fail some tests.

Right now this script only works on Windows and should work with most security endpoint solutions.

**How To**

Run the [runtests](runtests.bat) script and observe alerts coming to your EDR console. Cross-verify these alerts to check if your EDR solution identified them correctly. Most tests will just execute calc.exe but it can be easily modified to try to download and exec i.e. Mimikatz. DO NOT USE THIS SCRIPTS ON PRODUCTION SYSTEMS, INSTEAD DEPLOY THIS IN A VM WITH EDR. 

**Why**

Because it is hard to figure out how accurate EDR's are. Most EDR solutions are sold as silver bullet for security but it is actually difficult to check how many different malicious attacks are correctly identified and contained. [MITRE](https://attack.mitre.org/wiki/Main_Page) & [LOLBAS](https://github.com/api0cradle/LOLBAS ) do pretty good job at mapping common tools and techniques which are being used by attackers out there to pivot, execute code and progress through internal networks and this tool will executes these attacks to helps organizations verify the accuracy of deployed EDR product. 

**Weaponization** 

The script executes calc.exe. You can replace this easily with metasploit executable where needed but payloads will need to be modified to reflect this.

**Tested On**

* Windows 7 x86
* Windows 7 x64
* Windows 10 x64

**Coverage**

The following techniques are currently covered by this script: 

| [ATT&CK](https://attack.mitre.org/)  | [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | [Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter)  | Custom | Variants | [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation) | 
| ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | 
| T1197  | msiexec.exe  | MEMORY\PSWEBSTRING | winnt32 |  bitsadmin regsrv32  | BINARY\CMD\1 | 
| T1118  | diskshadow.exe  | MEMORY\PSWEBDATA | winrs | manage-bde.wsf + rundll32 JS | BINARY\CMD\2 | 
| T1170  | esentutl.exe | MEMORY\PSWEBOPENREAD | waitfor | | BINARY\CMD\3 |
| T1086  | replace.exe | MEMORY\NETWEBSTRING | .SettingContent-ms file  | | BINARY\PS\1 | 
| T1121  | SyncAppvPublishingServer | MEMORY\NETWEBDATA | | | BINARY\PS\2 |
| T1117  | hh.exe | MEMORY\NETWEBOPENREAD | | | BINARY\PS\3 |
| T1127  | ieexec.exe | MEMORY\PSWEBREQUEST | | | ENCODING\1 |
| T1047  | Setupapi | MEMORY\PSRESTMETHOD | | | ENCODING\2 |
| T1128  | Shdocvw | MEMORY\NETWEBREQUEST | | | ENCODING\3 |
| T1085  | csc.exe | MEMORY\PSSENDKEYS | | | PAYLOAD\CONCAT\1 |
| T1130  | advpack.dll | MEMORY\PSCOMWORD | | | PAYLOAD\CONCAT\2 |
| T1191  | Scriptrunner | MEMORY\PSCOMEXCEL | | | PAYLOAD\CONCAT\3 |
| T1202  | sc | MEMORY\PSCOMIE | | | PAYLOAD\REVERSE\1 |
| T1028  | Register-cimprovider | MEMORY\PSCOMMSXML | | | PAYLOAD\REVERSE\2 |
| T1053  | control.exe | MEMORY\PSINLINECSHARP | | | PAYLOAD\REVERSE\3 |
| T1216  | manage-bde.wsf | MEMORY\PSCOMPILEDCSHARP | | | PAYLOAD\FORCODE\1 |
| T1218  | AppVLP.exe | MEMORY\CERTUTIL | | | PAYLOAD\FORCODE\2 |
| T1033  | ScriptRunner.exe | DISK\PSWEBFILE | | | PAYLOAD\FORCODE\3 |
| T1140  | Pester.bat | DISK\PSBITS | | | PAYLOAD\FINCODE\1 |
| T1183  | powershellcustomhost.exe | DISK\BITSADMIN | | | PAYLOAD\FINCODE\2 |
| T1096  | PresentationHost.exe | DISK\CERTUTIL | | | PAYLOAD\FINCODE\3 |
| T1055  | Command Processor Registry | |
| T1015  | gpup.exe | |
| T1138  | VBoxDrvInst | | 
| | InstallHinfSection | |
| | Atbroker | |
| | msconfig | |
| | dnscmd | | 
| | java.exe | | 
| | WseClientSvc.exe | |


** Thanks ** 

Everyone working on awesome projects like [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) or [Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter) 