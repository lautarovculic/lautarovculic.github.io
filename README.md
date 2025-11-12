# Mobile Security Writeups

> **Professional mobile app security research** – Android/iOS reversing and exploitation techniques.

---

## What You'll Find

This repository contains **production-grade mobile security research** focused on identifying and exploiting vulnerabilities in Android and iOS applications. Each writeup includes:

- **Step-by-step exploitation techniques** with working proof-of-concepts
- **Real commands and code** you can replicate in your testing environment
- **Frida/Objection scripts** for instrumentation and runtime manipulation

---

## Research Areas

### **Mobile Reverse Engineering**
- **Android**: DEX/Smali analysis, APK unpacking, native library reversing (ARM/x86)
- **iOS**: Objective-C/Swift analysis, IPA extraction, dylib injection, class-dump workflows

### **Runtime Instrumentation & Hooking**
- **Frida**: JavaScript-based hooking, method tracing, SSL pinning bypass, root/jailbreak detection circumvention
- **Objection**: Automated mobile testing toolkit for iOS and Android
- **Custom scripts**: Anti-debugging bypass, emulator detection bypass, certificate validation patching

### **Application Attack Surface**
- **WebView Exploitation**: JavaScript bridge abuse, XSS in hybrid apps, file access vulnerabilities
- **Intent/Deep Link Abuse**: Intent redirection, path traversal, arbitrary component access
- **Content Provider Leakage**: SQL injection in providers, unauthorized data access
- **IPC Vulnerabilities**: Exposed broadcast receivers, vulnerable services

### **Access Control & Authorization**
- **IDOR (Insecure Direct Object Reference)**: Enumeration attacks, privilege escalation
- **Broken Authentication/Session Management**: Token manipulation, session fixation
- **API Security**: Mass assignment, parameter tampering, rate limiting bypass

### **Anti-Tampering & Hardening Bypass**
- **Root/Jailbreak Detection**: Bypassing integrity checks at runtime
- **Anti-Debugging**: Defeating PTRACE detection, debugger checks
- **Code Obfuscation**: Dealing with ProGuard, R8, obfuscation layers
- **Emulator Detection**: Circumventing AVD/simulator fingerprinting

---

## Tools & Techniques

| **Static Analysis** | **Dynamic Analysis** |
|----------------------|----------------------|
| - jadx, apktool, dex2jar  | - Frida, Objection, r2frida |
| - jd-gui, backsmali, bytecode-viewer | - Burp Suite, mitmproxy, netcat |
| - Ghidra, IDA Pro, Hopper | - ADB, iproxy, usbmuxd |
| - class-dump, otool, jtool2 | - Xposed, Magisk, Cydia Substrate |
| - keytool, jarsigner, apksigner | - Frida Gadget, Frida Server, LLDB |
| - radare2, strings, jadx-gui | - Wireshark, tcpdump, netcat |

---

## Getting Started

### Prerequisites
```bash
# Android tooling
brew install android-platform-tools jadx apktool

# iOS tooling (macOS)
brew install libimobiledevice ideviceinstaller

# Frida
pip install frida-tools objection

# Proxy setup
brew install mitmproxy
```

### Quick Testing Workflow
```bash
# 1. Install target app
adb install target.apk

# 2. Start Frida server on device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# 3. Launch Objection
objection -g com.target.app explore

# 4. Bypass SSL pinning
android sslpinning disable

# 5. Proxy traffic through Burp
adb shell settings put global http_proxy 192.168.1.100:8080
```
If you are using **Genymotion**, check: [burpCertAndroid](https://github.com/lautarovculic/burpCertAndroid)

---

## Who This Is For

- **Security Researchers** looking for mobile exploitation techniques
- **Penetration Testers** conducting mobile app assessments
- **Bug Bounty Hunters** targeting mobile attack surfaces
- **Mobile Developers** hardening apps against common vulnerabilities
- **Security Students** learning practical mobile hacking
