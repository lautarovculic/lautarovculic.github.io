**Description**: Welcome to the **Strings** Challenge! In this lab,your goal is to find the flag. The flag's format should be "`MHL{...}`". The challenge will give you a clear idea of how intents and intent filters work on android also you will get a hands-on experience using Frida APIs.

**Download**: https://lautarovculic.com/my_files/strings-MHL.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-strings

![[strings.png]]

Install the app with **ADB**
```bash
adb install -r strings-MHL.apk
```

We can see a **textview** that say **"Hello from C++"**..... smells like libraries.
Let's decompile it with **apktool**
```bash
apktool d strings-MHL.apk
```

Also, check the **source code** with **jadx**
The **package name** is `com.mobilehackinglab.challenge`.

Also, in the **AndroidManifest.xml** file we can found **two** activities.
```XML
<activity
    android:name="com.mobilehackinglab.challenge.Activity2"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="mhl"
            android:host="labs"/>
    </intent-filter>
</activity>
<activity
    android:name="com.mobilehackinglab.challenge.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

We can see that the **MainActivity** code load the library **challenge**.
```java
public final native String stringFromJNI();

static {
    System.loadLibrary("challenge");
}
```
But this is "out of scope" according MHL Team.

Also, there are a code that **never will be executed**
```java
public final void KLOW() {
    SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
    SharedPreferences.Editor editor = sharedPreferences.edit();
    Intrinsics.checkNotNullExpressionValue(editor, "edit(...)");
    SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault());
    String cu_d = sdf.format(new Date());
    editor.putString("UUU0133", cu_d);
    editor.apply();
}
```

This code is important to be executed because we need to “activate” the flag, to send an intent that we will see later in **`Activity2`**.

The `KLOW()` method **stores the current date** in `dd/MM/yyyy` format within the **SharedPreferences** under the key “**UUU0133**” in the **DAD4** file. This *ensures that another component of the app can validate the date as part of a specific logical flow*.

We can **force** the execution with **frida**.
But, before we can try understand **Activity2** code
There are a `decrypt()` method
```java
public final String decrypt(String algorithm, String cipherText, SecretKeySpec key) {
    Intrinsics.checkNotNullParameter(algorithm, "algorithm");
    Intrinsics.checkNotNullParameter(cipherText, "cipherText");
    Intrinsics.checkNotNullParameter(key, "key");
    Cipher cipher = Cipher.getInstance(algorithm);
    try {
        byte[] bytes = Activity2Kt.fixedIV.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        IvParameterSpec ivSpec = new IvParameterSpec(bytes);
        cipher.init(2, key, ivSpec);
        byte[] decodedCipherText = Base64.decode(cipherText, 0);
        byte[] decrypted = cipher.doFinal(decodedCipherText);
        Intrinsics.checkNotNull(decrypted);
        return new String(decrypted, Charsets.UTF_8);
    } catch (Exception e) {
        throw new RuntimeException("Decryption failed", e);
    }
}
```

We can use https://cyberchef.org for this work.
The **IV** is hardcoded in `Activity2Kt` class, with the value `1234567890123456`

![[strings2.png]]

The output is **`mhl_secret_1337`**.
This must be converted to **base64** according the logic of the app, so, the value is `bWhsX3NlY3JldF8xMzM3`.

This logic can be seem here
```java
if (uri != null && Intrinsics.areEqual(uri.getScheme(), "mhl") && Intrinsics.areEqual(uri.getHost(), "labs")) {
    String base64Value = uri.getLastPathSegment();
    byte[] decodedValue = Base64.decode(base64Value, 0);
}
```

So, the app will decode the base64 for us, we just pass this **via Intent**.
And here's the **javascript** script for **frida**
```javascript
Java.perform(function () {
    console.log("[+] Starting combined exploit script...");

    // Hooking KLOW() method in MainActivity
    try {
        var MainActivity = Java.use('com.mobilehackinglab.challenge.MainActivity');
        MainActivity.KLOW.implementation = function () {
            console.log("[+] Forcing SharedPreferences write via KLOW method");
            this.KLOW();
        };
    } catch (e) {
        console.log("[-] Error hooking KLOW: " + e.message);
    }

    // Enumerate MainActivity after 1-second delay
    setTimeout(function () {
        console.log("[+] Searching for MainActivity instance...");

        Java.choose("com.mobilehackinglab.challenge.MainActivity", {
            onMatch: function (instance) {
                console.log("[+] MainActivity instance found. Invoking KLOW...");
                try {
                    instance.KLOW();
                    console.log("[+] KLOW executed successfully on MainActivity instance.");
                } catch (e) {
                    console.log("[-] Error invoking KLOW on MainActivity instance: " + e.message);
                }
            },
            onComplete: function () {
                console.log("[*] MainActivity enumeration completed.");
            }
        });
    }, 1000);

    // Enumerate Activity2 after 5-second delay
    setTimeout(function () {
        console.log("[+] Searching for Activity2 instance...");

        Java.choose("com.mobilehackinglab.challenge.Activity2", {
            onMatch: function (instance) {
                console.log("[+] Activity2 instance found. Calling cd() method...");
                try {
                    var dateResult = instance.cd();
                    console.log("[*] cd() method returned: " + dateResult);
                } catch (e) {
                    console.log("[-] Error calling cd(): " + e.message);
                }

                console.log("[+] Attempting to retrieve the flag...");
                try {
                    var flag = instance.getflag();
                    console.log("[+] Flag obtained: " + flag);
                } catch (e) {
                    console.log("[-] Failed to retrieve flag: " + e.message);
                }
            },
            onComplete: function () {
                console.log("[*] Activity2 enumeration completed.");
            }
        });
    }, 5000);
});
```

This script will **ensure** that all code will be **executed** enumerating all.
And, we can see that it's work
```bash
[+] Starting combined exploit script...
[+] Searching for MainActivity instance...
[+] MainActivity instance found. Invoking KLOW...
[+] Forcing SharedPreferences write via KLOW method
[+] KLOW executed successfully on MainActivity instance.
[*] MainActivity enumeration completed.
[+] Searching for Activity2 instance...
[*] Activity2 enumeration completed.
```

You can run the **frida command** when you already launch the app and then
```bash
frida -U -p $(frida-ps -Uai | grep "com.mobilehackinglab.challenge" | awk '{print $1}') -l script.js
```
This will take the **PID** value of the **Strings** app.

And here's the `DAD4.xml` file
```bash
ginkgo:/data/data/com.mobilehackinglab.challenge/shared_prefs # pwd
/data/data/com.mobilehackinglab.challenge/shared_prefs
ginkgo:/data/data/com.mobilehackinglab.challenge/shared_prefs # ls
DAD4.xml
ginkgo:/data/data/com.mobilehackinglab.challenge/shared_prefs # cat DAD4.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="UUU0133">31/12/2024</string>
</map>
ginkgo:/data/data/com.mobilehackinglab.challenge/shared_prefs #
```

Now we can launch the **Activity2** via **ADB**
```bash
adb shell am start -a android.intent.action.VIEW -n com.mobilehackinglab.challenge/.Activity2 -d "mhl://labs/bWhsX3NlY3JldF8xMzM3"
```

This will drop us a Toast message saying **Success**.
We can try **dump the memory now** with **fridump**
You can find the tool here: https://github.com/Nightbringer21/fridump/

Clone the repo and then, in a *new terminal* attach the app and run **fridump**

![[strings3.png]]

```bash
fridump.py -U -s Strings
```
And
```bash
strings dump/strings.txt | grep MHL{
```

You will get the flag!

I hope you found it useful (: