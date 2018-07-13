# EDR-Testing-Script

This repository contains simple script to test your EDR solution against few Mitre ATT&CK framework tests (with some extras). This project is very much in its infancy right now. Only a small subset of tests are presently added but more will be added later. Chances are this script will be redesigned to facilitate this in the future. It is written as a single batch script so it can be easily uploaded and run (as opposed to un-zipped, compiled and installed). It can run either as a normal user or as Administrator.

Right now this script only works on Windows and should work with most security endpoint solutions.

**How To**

Run the script and observe alerts coming to your EDR console. Cross-verify these alerts to check if your EDR solution identified them correctly. Most tests will just execute calc.exe but it can be easily modified to try to download and exec i.e. Mimikatz.

**Why**

Because it is hard to figured out how accurate EDR's are. Most endpoint solutions are sold as magic bullet for security but it is actually difficult to verify how much these products actually detect from the most common malicious techniques. [MITRE](https://attack.mitre.org/wiki/Main_Page) & [LOLBAS](https://github.com/api0cradle/LOLBAS) do pretty good job at mapping common tools and techniques which are being used by attackers out there to pivot, execute code and progress through internal networks. The aim of this tool is to help and verify if the use of tools and techniques is indeed detected by your endpoint solution.

**Weaponization** 

The script currently tries to execute only calc.exe via various methods. You can replace this easily with metasploit executable where needed.

**Tested On**

* Windows 7 x86
* Windows 7 x64
* Windows 10 x64


