**Description**: Last night, most employees' mobile devices were compromised, putting them at significant risk of leaking personal and private information. We require your expertise in digital forensics to help investigate this breach.
**Difficulty**: Easy
**Category**: Mobile / Forensics

![[htb_droidphish1.png]]

Download the **`.zip`** file and extract with the password: `hacktheblue`

```file
file DroidPhish.dd
```
Output:
```bash
DroidPhish.dd: Linux rev 1.0 ext4 filesystem data, UUID=e98cc545-b7fe-4ba9-8b33-2fb9bba476d6, volume name "Android-x86" (needs journal recovery) (extents) (large files)
```

We got a **`filesystem dump`** in `ext4` format. Basically, a `VM Android-x86`.
Let's *mount* this.
```bash
mkdir mount
```

```bash
sudo mount -t ext4 -o ro,noload,loop DroidPhish.dd ./mount
```

Now, inside of `mount` directory we can see the **dumped** content.
Let's start with the *questions*.

### Provide the last boot time of the device in UTC format.
This was honestly the hardest question for me, as the file system is a bit different than what I usually see on my rooted device.

To complete this question I had to overuse the `grep` command and also `find` to search for files and expressions.
This dude: https://stackoverflow.com/questions/74884067/where-is-the-last-boot-log-of-android

Give me the hint necessary for start searching. Inside of `/data/misc` directory.
Searching, we'll use the `stat` command.
Inside of `/mount/android-9.0-r2/data/misc/bootstat` directory, we have the **`factory_reset_current_time`** file.
```bash
stat factory_reset_current_time
```
Output:
```bash
File: factory_reset_current_time
  Size: 0         	Blocks: 0          IO Block: 4096   regular empty file
Device: 7,0	Inode: 49388       Links: 1
Access: (0600/-rw-------)  Uid: ( 1000/ lautaro)   Gid: ( 1007/ UNKNOWN)
Access: 2024-11-15 15:18:22.000000000 -0300
Modify: 2024-11-24 09:05:19.000000000 -0300
Change: 2024-11-24 09:05:19.954315000 -0300
Birth: 2024-11-15 15:18:22.810376000 -0300
```

**Answer**: `2024-11-24 12:05:19`

### The user was exposed to a phishing attack. Provide the name of the email app used as the attack vector.
This seems easy, since we **can enumerate all installed apps** in `/data/data/` directory, we just need go here and then:
```bash
pwd && ls | grep mail
```
Output:
```bash
/<REDACTED>/mount/android-9.0-r2/data/data
ch.protonmail.android
```

**Answer**: `Proton Mail`

### Provide the title of the phishing email.
Now we just can go to the `ch.protonmail.android` app directory.
Inside we can see the typical app structure in the file system:
```bash
app_events  app_textures  app_webview  cache  code_cache  databases  files  lib  no_backup  shared_prefs
```

Let's inspect the `databases` directory. Where, some apps stored in `plaintext` or (sometimes) `encrypted`.
The structure is in `SQLite` format. We can use this tool for a comprehensive information.
We can see the `db-mail` file, that is a `SQLite` file:
```bash
file db-mail
```
Output:
```bash
db-mail: SQLite 3.x database, user version 27 (0x1b), last written using SQLite version 3022000, writer version 2, read version 2, file counter 13, database pages 263, cookie 0x81, schema 4, largest root page 174, UTF-8, version-valid-for 13
```

Open with **`sqlite3`** and let's inspect the content.
```bash
sqlite> .headers on
sqlite> .tables
sqlite> select subject from MessageEntity;
```
And, after take a look, we can found the **correct subject**:

**Answer**: `Celebrating 3 Years of Success – Thank You!`
*NOTE*: Be careful, the `–` in the title isn't -

### Provide the time in UTC when the phishing email was received.
The `time` field from the `MessageEntity` table is stored as **UNIX epoch** (in *seconds*).  
We can extract it using:
```bash
sqlite> select subject, time from MessageEntity;
```
Output:
```bash
Celebrating 3 Years of Success – Thank You!|1732467880
```

Now, convert the **timestamp to human-readable format**:
```bash
date -d @1732467880 -u
```
Output:
```bash
Sun Nov 24 05:04:40 PM UTC 2024
```
Although this seems like the correct reception time, the challenge **doesn't accept it**.
After *testing around the timestamp boundaries*, the **correct answer** turned out to be:
`2024-11-24 17:04:42`
Likely due to a **1-2 second desync** between what the system stores and how HTB validates it? or the *tricky question* that ask for *received email* and the *dump* show the *send* date.

**Answer**:  `2024-11-24 17:04:42`

### Provide the download URL for the malicious application.
Let's search this.
Using `sqlite3` we can make this query:
```bash
sqlite> slect messageId from MessageEntity where subject like '%3 Years%';
```

Now we have the `messageId`:
```bash
UgTdGYhjCQNEW9gFvY__mMjF4jQh-iLkgiWqItzvcoxsjA7OzIwv9KGh19LorJnvgSdZ6aWNl-G-0fdBIOL2RQ==
```
So we can search in the **body** of the message, we can see the **`MessageBodyEntity`** table.
```bash
sqlite> select * from MessageBodyEntity where messageId = 'UgTdGYhjCQNEW9gFvY__mMjF4jQh-iLkgiWqItzvcoxsjA7OzIwv9KGh19LorJnvgSdZ6aWNl-G-0fdBIOL2RQ==';
```

Although the **body of the phishing email is encrypted using PGP** (as expected in Proton Mail), we were **able to locate the download link through raw memory inspection**.
Just run:
```bash
strings DroidPhish.dd | grep -iE 'http.*apk' | head
```
Output:
```bash
http://schemas.android.com/apk/res/android
2@https://www.gstatic.com/gsa_dynamic_updates/prod/main_apk.gz.jar8
2@https://www.gstatic.com/gsa_dynamic_updates/prod/main_apk.gz.jar8
'http://schemas.android.com/apk/res-auto
*http://schemas.android.com/apk/res/android
https://protonmail.en.uptodown.com/androidProton Mail for Android - Download the APK from Uptodown
tWorking around action mode LG Email bug in WebView (http://crbug.com/651706). APK name: com.lge.email, versionCode:
*http://schemas.android.com/apk/res/android
        <a href="https://provincial-consecutive-lbs-boots.trycloudflare.com/Booking.apk" target="_blank">Download Booking</a>
'http://schemas.android.com/apk/res-auto
```
We found the **download link**!

**Answer**: `https://provincial-consecutive-lbs-boots.trycloudflare.com/Booking.apk`

### Provide the SHA-256 hash of the malicious application.
Obviously, the link is **down**.
But, **the user was downloaded the APK**!
So, the `.apk` file is located in the typical `/data/media/0/Download/` directory.

Just run:
```bash
find mount/android-9.0-r2/ -iname "Booking.apk" -exec sha256sum {} \;
```
Output:
```bash
af081cd26474a6071cde7c6d5bd971e61302fb495abcf317b4a7016bdb98eae2  mount/android-9.0-r2/data/media/0/Download/Booking.apk
```

**Answer**: `af081cd26474a6071cde7c6d5bd971e61302fb495abcf317b4a7016bdb98eae2`

### Provide the package name of the malicious application.
We can **infer the malicious package** by checking the **installed apps**:
```bash
ls mount/android-9.0-r2/data/data/
```
By **correlating with the phishing email's content** (which *included* a link to `Booking.apk`), we spot the **suspicious** package.

**Answer**: `com.hostel.mount`

### Provide the installation timestamp for the malicious application in UTC.
Initially, we tried to **retrieve the install timestamp from the usual location**:
```bash
grep -A 10 'com.hostel.mount' mount/android-9.0-r2/data/system/packages.xml
```

Inside that file, the `<package>` entry for `com.hostel.mount` contained the attribute:
```XML
it="1935f2b00f3"
```
Which converts to:
`2024-11-24 17:05:59 UTC`
However, **this value was not accepted by the challenge**.

As a fallback, we **inspected the actual file system metadata of the installed APK with**:
```bash
stat mount/android-9.0-r2/data/app/com.hostel.mount*/base.apk
```

We found:
```bash
Change: 2024-11-24 14:14:34.098000000 -0300
```
Converted to UTC:
```bash
2024-11-24 17:14:34
```
This `Change` time **reflects the moment when the APK was written** to `/data/app/`, which indicates the **effective installation time**.
Since `/data/data/` **contains runtime data and configurations**, *not the APK itself*, we moved to `/data/app/`, where the **system stores the actual installed package** (`base.apk`).

**Answer**: `2024-11-24 17:14:34`

### Provide the number of runtime permissions granted to the malicious application.
We initially analyzed the file:
```bash
grep -A 20 'com.hostel.mount' mount/android-9.0-r2/data/system/packages.xml | grep perm
```
Output:
```bash
<perms>
    <item name="android.permission.FOREGROUND_SERVICE" granted="true" flags="0" />
    <item name="android.permission.RECEIVE_BOOT_COMPLETED" granted="true" flags="0" />
    <item name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" granted="true" flags="0" />
    <item name="com.android.alarm.permission.SET_ALARM" granted="true" flags="0" />
    <item name="android.permission.INTERNET" granted="true" flags="0" />
    <item name="android.permission.CHANGE_WIFI_STATE" granted="true" flags="0" />
    <item name="android.permission.ACCESS_NETWORK_STATE" granted="true" flags="0" />
    <item name="android.permission.DISABLE_KEYGUARD" granted="true" flags="0" />
    <item name="android.permission.SET_WALLPAPER" granted="true" flags="0" />
    <item name="android.permission.REQUEST_DELETE_PACKAGES" granted="true" flags="0" />
    <item name="android.permission.ACCESS_WIFI_STATE" granted="true" flags="0" />
    <item name="android.permission.WAKE_LOCK" granted="true" flags="0" />
</perms>
```

Inside the `<package>` block for `com.hostel.mount`, we found a `<perms>` section with exactly **12** `<item>` elements marked as `granted="true"`:
However, the challenge **did not accept `12` as a valid answer**.

To investigate further, we **decompiled** the APK using `apktool`:
```bash
sudo cp mount/android-9.0-r2/data/media/0/Download/Booking.apk .
```

```bash
apktool d Booking.apk
```

```bash
cat AndroidManifest.xml | grep perm
```
Inside `AndroidManifest.xml`, we found that the application declares many **dangerous** and **runtime** permissions.
Even though t**hose were not yet granted**, *it's possible that the challenge validator* counted **requested runtime permissions** as well — or **simply miscounted due to internal logic**.

While the **XML clearly shows 12 granted permissions**, the correct *accepted answer for the challenge* was:

**Answer**: `13`

### Identify the C2 IP address and port that the malicious application was programmed to connect to.
After trying **several way**s to search for IPs both in the `.dd` and in the application *decompiled with `apktool`*, e.g.
```bash
strings DroidPhish.dd | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}' | sort -u
```

```bash
grep -Er "Socket|connect|URLConnection|newInstance" smali/ | less
```

```bash
grep -Erho ':[0-9]{2,5}' smali/ | sort -u
```

```bash
grep -Erho 'http[s]?://[^"]+' smali/ | sort -u
```

**But nothing worked**.
So I decided to look at the **java code and search for classes**.
You can use **MobSF** or simply **jadx**.

After search some time, I found the `initializeService.java` class.
Here's the **java code**:
```java
package com.hostel.gybbpabtniopoetzeacrkmlxdhuvgpvnwtahmsaxmtnaltfrgf2.keydkuycdcczonreivsieapzgrzkejxcowwsziydpvouihgqnu3;

import android.app.Service;
[...]
[...]
IMPORTS
[...]
[...]
import java.util.List;

/* loaded from: classes.dex */
public class initializeService extends Service {
    public static String ClientHost = "My4xMjEuMTM5Ljgy";
    public static String ClientPort = "MTA4MjQ=";
    public static String HideType = "C";
    public static Context appContext;
    public static String ifScreenShot;
    static initializeService st;
    public static String ConnectionKey = utilities.eosjvohlvdszzfnoawempbvgtfrhiukwdrdirywuhpeetixbkj45("MHhTMXJ4NTg=");
    public static String uninstall = "on";
    public static String CLINAME = "Client";
    public static List<PacketClass> Li = null;
    public static List<niqiqgqxxajrlskldmrbzmbkhlvayewbedibhmfoaetoujkdjh6> Lcl = null;
    public static long eco = -1;
    public static int plg = -1;
    public static int inx = -1;
    public static String[] cmn = {"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""};
    public static boolean k = false;
    public static boolean klive = false;
    public static boolean FORCA = false;
    public static boolean FORSC = false;
    public static String usdtadress = "";
    public static AccessService MyAccess = null;
    public static boolean allok = false;
    public static BroadcastReceiver br = null;
    public static BroadcastReceiver daterecever = null;
[...]
[...]
[...]
[...]
[...]
```

Notice this code lines:
```java
public static String ClientHost = "My4xMjEuMTM5Ljgy";
public static String ClientPort = "MTA4MjQ=";
```
We were never going to find the IP because it is **base64**!
```bash
echo "$(echo 'My4xMjEuMTM5Ljgy' | base64 -d):$(echo 'MTA4MjQ=' | base64 -d)"
```

**Answer**: `3.121.139.82:10824`

I hope you found it useful (: