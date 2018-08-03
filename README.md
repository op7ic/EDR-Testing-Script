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

| ATT&CK  | LOLBAS | Invoke-CradleCrafter | Custom | Variants |
| ------------- | ------------- | ------------- | ------------- | ------------- |
| T1197  | msiexec.exe  | MEMORY\PSWEBSTRING | winnt32 |  bitsadmin regsrv32  |
| T1118  | diskshadow.exe  | MEMORY\PSWEBDATA | winrs | manage-bde.wsf + rundll32 JS |
| T1170  | esentutl.exe | MEMORY\PSWEBOPENREAD | waitfor | |
| T1086  | replace.exe | MEMORY\NETWEBSTRING | .SettingContent-ms file  | |
| T1121  | SyncAppvPublishingServer | MEMORY\NETWEBDATA | |
| T1117  | hh.exe | MEMORY\NETWEBOPENREAD |
| T1127  | ieexec.exe | MEMORY\PSWEBREQUEST |
| T1047  | Setupapi | MEMORY\PSRESTMETHOD | 
| T1128  | Shdocvw | MEMORY\NETWEBREQUEST |
| T1085  | csc.exe | MEMORY\PSSENDKEYS |
| T1130  | advpack.dll | MEMORY\PSCOMWORD |
| T1191  | Scriptrunner | MEMORY\PSCOMEXCEL |
| T1202  | sc | MEMORY\PSCOMIE |
| T1028  | Register-cimprovider | MEMORY\PSCOMMSXML |
| T1053  | control.exe | MEMORY\PSINLINECSHARP |
| T1216  | manage-bde.wsf | MEMORY\PSCOMPILEDCSHARP |
| T1218  | AppVLP.exe | MEMORY\CERTUTIL |
| T1033  | ScriptRunner.exe | DISK\PSWEBFILE | 
| T1140  | Pester.bat | DISK\PSBITS |
| T1183  | powershellcustomhost.exe | DISK\BITSADMIN |
| T1096  | PresentationHost.exe | DISK\CERTUTIL |
| T1055  | Command Processor Registry | |
| T1015  | gpup.exe | |
| T1138  | VBoxDrvInst | | 
| | InstallHinfSection | |
| | Atbroker | |
| | msconfig | |
| | dnscmd | | 
| | java.exe | | 
| | WseClientSvc.exe | |
