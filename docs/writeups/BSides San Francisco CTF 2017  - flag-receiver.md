**Description**: Here is a simple mobile application that will hand you the flag.. if you ask for it the right way.
P.S, it is meant to have a blank landing activity :) Use string starting with Flag:
**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/flagstore.apk

![[bside_flagstore1.png]]

Install the **apk** with **adb**
```bash
adb install -r flagstore.apk
```

Then, decompile it with **apktool**
```bash
apktool d flagstore.apk
```
We can see that we have an **"empty"** activity.
Let's inspect the **source code** with **jadx**

We can see in **strings.xml** some interesting harcoded strings
```XML
<string name="passphrase">LetMeIn</string>  
<string name="str1">OsjPwhjaMjAzZGFmM</string>  
<string name="str2">QklEsuOGNlZTRkMjEhNGUyZD</string>  
<string name="str3">wgHoNi[nvVfptxF@hpsd9DhrM@sz]</string>
```
Keep this in mind if we need this information in next steps.

Here's the **AndroidManifest.xml** file
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    android:versionCode="1"  
    android:versionName="1.0"  
    package="com.flagstore.ctf.flagstore"  
    platformBuildVersionCode="24"  
    platformBuildVersionName="7">  
    <uses-sdk  
        android:minSdkVersion="15"  
        android:targetSdkVersion="24"/>  
    <permission  
        android:name="ctf.permissions._MSG"  
        android:protectionLevel="signature"  
        android:description="@string/res_0x7f060021_android_permission__msg"/>  
    <permission  
        android:name="ctf.permissionn._SEND"  
        android:description="@string/res_0x7f060021_android_permission__msg"/>  
    <application  
        android:theme="@style/AppTheme"  
        android:label="@string/app_name"  
        android:icon="@mipmap/ic_launcher"  
        android:allowBackup="true"  
        android:supportsRtl="true">  
        <activity android:name="com.flagstore.ctf.flagstore.MainActivity">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
        <activity android:name="com.flagstore.ctf.flagstore.Send_to_Activity"/>  
        <activity android:name="com.flagstore.ctf.flagstore.CTFReceiver"/>  
        <receiver  
            android:name="com.flagstore.ctf.flagstore.Send_to_Activity"  
            android:exported="true"/>  
    </application>  
</manifest>
```
We can see four things
- `com.flagstore.ctf.flagstore` is the package name of the android app.
- Two permissions, `ctf.permissions._MSG` and `ctf.permissionn._SEND`
- Three activities, `MainActivity`, `Send_to_Activity` and `CTFReceiver`
- And one receiver called `Send_to_Activity` (used in the activity with the same name)

We can see in the **Manifest** class, we just can look that the permissions are called.
And in the **MainActivity**
```java
public class MainActivity extends Activity {  
    @Override // android.app.Activity  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        TextView tv = new TextView(getApplicationContext());  
        tv.setText("To-do: UI pending");  
        setContentView(tv);  
        IntentFilter filter = new IntentFilter();  
        filter.addAction("com.flagstore.ctf.INCOMING_INTENT");  
        BroadcastReceiver receiver = new Send_to_Activity();  
        registerReceiver(receiver, filter, Manifest.permission._MSG, null);  
    }  
}
```

We can see that the intent is used for **launch** the **Send_to_Activity** when is received.
The **Send_to_Activity** look like
```java
public class Send_to_Activity extends BroadcastReceiver {  
    @Override // android.content.BroadcastReceiver  
    public void onReceive(Context context, Intent intent) {  
        String msgText = intent.getStringExtra("msg");  
        if (msgText.equalsIgnoreCase("OpenSesame")) {  
            Log.d("Here", "Intent");  
            Intent outIntent = new Intent(context, (Class<?>) CTFReceiver.class);  
            context.startActivity(outIntent);  
            return;  
        }  
        Toast.makeText(context, "Ah, ah, ah, you didn't say the magic word!", 1).show();  
    }  
}
```
We can craft an **adb** command with this information of both classes.
```bash
adb shell am broadcast -a com.flagstore.ctf.INCOMING_INTENT -e "msg" "OpenSesame"
```
Send an **intent** with the **extra** string **msg**, and the **value** is **`OpenSesame`**

And we can see that a new activity is launched
![[bside_flagstore2.png]]
We can see just an **button** with the label **BROADCAST**, which means that we need send an **Broadcast** message.

Here's the **onCreate** method in **CTFReceiver** class
```java
public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        TextView tv = new TextView(this);  
        tv.setText("Clever Person!");  
        Button button = new Button(this);  
        button.setText("Broadcast");  
        setContentView(button);  
        button.setOnClickListener(new View.OnClickListener() { // from class: com.flagstore.ctf.flagstore.CTFReceiver.1  
            @Override // android.view.View.OnClickListener  
            public void onClick(View v) {  
                Intent intent = new Intent();  
                intent.setAction("com.flagstore.ctf.OUTGOING_INTENT");  
                String a = CTFReceiver.this.getResources().getString(R.string.str3) + "fpcMpwfFurWGlWu`uDlUge";  
                String b = Utilities.doBoth(CTFReceiver.this.getResources().getString(R.string.passphrase));  
                String name = getClass().getName().split("\\.")[4];  
                String c = Utilities.doBoth(name.substring(0, name.length() - 2));  
                String output = CTFReceiver.this.getPhrase(a, b, c);  
                intent.putExtra("msg", output);  
                CTFReceiver.this.sendBroadcast(intent);  
            }  
        });  
    }  
  
    static {  
        System.loadLibrary("native-lib");  
    }
```

Which load an **native-lib** binary, that we can inspect with **ghidra**
In the function `Java_com_flagstore_ctf_flagstore_CTFReceiver_getPhrase`
We can found this piece of code
```C
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  __src = (char *)(**(code **)(*param_1 + 0x2a4))(param_1,param_3,0);
  __src_00 = (char *)(**(code **)(*param_1 + 0x2a4))(param_1,param_4,0);
  __src_01 = (char *)(**(code **)(*param_1 + 0x2a4))(param_1,param_5,0);
  local_e4 = 0x5e;
  local_e8 = 0x767d726c;
  local_ec = 0x50696a4d;
  local_f0 = 0x655f6f42;
  local_f4 = 0x77644144;
  local_f8 = 0x4e454866;
  local_fc = 0x487e4140;
  ```
Following the logic of the code, we get the string `@A~HfHENDAdwBo_eMjiPlr}v^`
Which in the java code we have
```java
String a = CTFReceiver.this.getResources().getString(R.string.str3) + "fpcMpwfFurWGlWu`uDlUge";
```
In the **strings.xml** file, we can complete the **a** variable
```text
wgHoNi[nvVfptxF@hpsd9DhrM@sz]fpcMpwfFurWGlWu`uDlUge
```

Using **Utilities** and **CTFReceiver** classes, I do this **javascript** code for **frida** for `hook functions and values`
```javascript
Java.perform(function() {
    // Hook to CTFReceiver and Utilities class
    var CTFReceiver = Java.use("com.flagstore.ctf.flagstore.CTFReceiver");
    var Utilities = Java.use("com.flagstore.ctf.flagstore.Utilities");

    // Hook for intercepting the getPhrase method
    CTFReceiver.getPhrase.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(a, b, c) {
        console.log("Intercepting getPhrase");
        console.log("Value of 'a':", a);
        console.log("Value of 'b':", b);
        console.log("Value of 'c':", c);

        // Call original method
        var result = this.getPhrase(a, b, c);
        console.log("getPhrase:", result);
        return result;
    };

    // Hook for intercept the doBoth Methods from Utilities class
    Utilities.doBoth.overload('java.lang.String').implementation = function(input) {
        console.log("Intercepting doBoth with passphrase:", input);

        var result = this.doBoth(input);
        console.log("doBoth:", result);
        return result;
    };

    // Hook for capture sendBroadcast and see the intent
    var Context = Java.use("android.content.Context");
    Context.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
        var action = intent.getAction();
        var extras = intent.getExtras();
        if (action === "com.flagstore.ctf.OUTGOING_INTENT") {
            console.log("Intercepting Intent with ACTION:", action);
            console.log("Send Intent:", extras.getString("msg"));
        }
        this.sendBroadcast(intent); // Call original method
    };
});
```

Setup frida in your emulator and then, get the process app running the **broadcast** view activity.
Then, run automatically
```bash
frida -U -p $(frida-ps -Uai | grep "flagstore" | awk '{print $1}') -l script.js
```
The `-U` parameter is for attach frida to the process (`-P`) that is the output of the *middle command*, then, run the script that I share previously.
When we press the **BROADCAST** button, we get the following output
```bash
[Pixel 2::PID::8893 ]-> Intercepting getPhrase
Value of 'a': wgHoNi[nvVfptxF@hpsd9DhrM@sz]fpcMpwfFurWGlWu`uDlUge
Value of 'b': NTYxMDdjZTljZTkeYhQwNmRhMDhmMzZkOGNlZTRkMjEhNGUyZDhmNDEtZTVmMhYhODAeMGMyZTU?

Value of 'c': MzIWYmUWYzgyOTFkMmMaMjAzZGFmMDViNDMyODkiODYzMDEyMzMWZmFjMjghNhYtYmIwYTAiYTA?

getPhrase: CongratsGoodWorkYouFoundIBTZGxaOEUj[Q]@MFEu]GZjMS{\wndTDzx[HighR~p|KyZ{IWA}Y
```

So, we have **half**-flag. We need complete this.
Going back to the library, I notice that in some part of the code in C from `Java_com_flagstore_ctf_flagstore_CTFReceiver_getPhrase`
We have this
```C
  do {
    param1 = local_ae[iVar1] ^ local_61[iVar1] ^ *(byte *)((int)&local_fc + iVar1);
    local_149[iVar1] = param1;
    printf("%c\n",param1);
    iVar1 = iVar1 + 1;
  } while (iVar1 != 0x4c);
  local_fd = 0;
  printf("Here is your Reply: %s",(char *)local_149);
  (**(code **)(*param_1 + 0x29c))(param_1,local_149);
  if (*(int *)(in_GS_OFFSET + 0x14) == local_14) {
    return;
  }
```

And now we just need resolve this with python
```python
a = "@A~HfHENDAdwBo_eMjiPlr}v^wgHoNi[nvVfptxF@hpsd9DhrM@sz]fpcMpwfFurWGlWu`uDlUge"
b = "NTYxMDdjZTljZTkeYhQwNmRhMDhmMzZkOGNlZTRkMjEhNGUyZDhmNDEtZTVmMhYhODAeMGMyZTU?"
c = "MzIWYmUWYzgyOTFkMmMaMjAzZGFmMDViNDMyODkiODYzMDEyMzMWZmFjMjghNhYtYmIwYTAiYTA?"

output = ""

for char in range(len(a)):
    output += chr(ord(a[char]) ^ ord(b[char]) ^ ord(c[char]))

print(output)
```

Run the python script and we get the flag
```text
CongratsGoodWorkYouFoundItIHopeYouUsedADBFlag:TheseIntentsAreFunAndEasyToUse
```


I hope you found it useful (: