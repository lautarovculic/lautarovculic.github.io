**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/illintentions.apk

![[illintentions1.png]]

Install the **apk** with **adb**
```bash
adb install -r illintentions.apk
```

Let's decompile the content with **apktool**.
```bash
apktool d illintentions.apk
```
And let's check the **source code** with **jadx** (GUI version)
We can see that the **package name** is `com.example.hellojni`

So, after read the code some minutes, we have the **MainActivity**
```java
public class MainActivity extends Activity {  
    @Override // android.app.Activity  
    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        TextView tv = new TextView(getApplicationContext());  
        tv.setText("Select the activity you wish to interact with.To-Do: Add buttons to select activity, for now use Send_to_Activity");  
        setContentView(tv);  
        IntentFilter filter = new IntentFilter();  
        filter.addAction("com.ctf.INCOMING_INTENT");  
        BroadcastReceiver receiver = new Send_to_Activity();  
        registerReceiver(receiver, filter, Manifest.permission._MSG, null);  
    }  
}
```
Here we can see an **intent**.

We have a **broadcast receiver** in **Send_to_Activity**
```java
public class Send_to_Activity extends BroadcastReceiver {  
    @Override // android.content.BroadcastReceiver  
    public void onReceive(Context context, Intent intent) {  
        String msgText = intent.getStringExtra("msg");  
        if (msgText.equalsIgnoreCase("ThisIsTheRealOne")) {  
            Intent outIntent = new Intent(context, (Class<?>) ThisIsTheRealOne.class);  
            context.startActivity(outIntent);  
        } else if (msgText.equalsIgnoreCase("IsThisTheRealOne")) {  
            Intent outIntent2 = new Intent(context, (Class<?>) IsThisTheRealOne.class);  
            context.startActivity(outIntent2);  
        } else if (msgText.equalsIgnoreCase("DefinitelyNotThisOne")) {  
            Intent outIntent3 = new Intent(context, (Class<?>) DefinitelyNotThisOne.class);  
            context.startActivity(outIntent3);  
        } else {  
            Toast.makeText(context, "Which Activity do you wish to interact with?", 1).show();  
        }  
    }  
}
```

The **ThisIsTheRealOne** class
```java
public class ThisIsTheRealOne extends Activity {  
    public native String computeFlag(String str, String str2);  
  
    public native String definitelyNotThis(String str, String str2, String str3);  
  
    public native String orThat(String str, String str2, String str3);  
  
    public native String perhapsThis(String str, String str2, String str3);  
  
    @Override // android.app.Activity  
    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        TextView tv = new TextView(this);  
        tv.setText("Activity - This Is The Real One");  
        Button button = new Button(this);  
        button.setText("Broadcast Intent");  
        setContentView(button);  
        button.setOnClickListener(new View.OnClickListener() { // from class: com.example.application.ThisIsTheRealOne.1  
            @Override // android.view.View.OnClickListener  
            public void onClick(View v) {  
                Intent intent = new Intent();  
                intent.setAction("com.ctf.OUTGOING_INTENT");  
                String a = ThisIsTheRealOne.this.getResources().getString(R.string.str2) + "YSmks";  
                String b = Utilities.doBoth(ThisIsTheRealOne.this.getResources().getString(R.string.dev_name));  
                String c = Utilities.doBoth(getClass().getName());  
                intent.putExtra("msg", ThisIsTheRealOne.this.orThat(a, b, c));  
                ThisIsTheRealOne.this.sendBroadcast(intent, Manifest.permission._MSG);  
            }  
        });  
    }  
  
    static {  
        System.loadLibrary("hello-jni");  
    }  
}
```

The **IsThisTheRealOne**
```java
public class IsThisTheRealOne extends Activity {  
    public native String computeFlag(String str, String str2);  
  
    public native String definitelyNotThis(String str, String str2, String str3);  
  
    public native String orThat(String str, String str2, String str3);  
  
    public native String perhapsThis(String str, String str2, String str3);  
  
    @Override // android.app.Activity  
    public void onCreate(Bundle savedInstanceState) {  
        getApplicationContext();  
        super.onCreate(savedInstanceState);  
        TextView tv = new TextView(this);  
        tv.setText("Activity - Is_this_the_real_one");  
        Button button = new Button(this);  
        button.setText("Broadcast Intent");  
        setContentView(button);  
        button.setOnClickListener(new View.OnClickListener() { // from class: com.example.application.IsThisTheRealOne.1  
            @Override // android.view.View.OnClickListener  
            public void onClick(View v) {  
                Intent intent = new Intent();  
                intent.setAction("com.ctf.OUTGOING_INTENT");  
                String a = IsThisTheRealOne.this.getResources().getString(R.string.str3) + "\\VlphgQbwvj~HuDgaeTzuSt.@Lex^~";  
                String b = Utilities.doBoth(IsThisTheRealOne.this.getResources().getString(R.string.app_name));  
                String name = getClass().getName();  
                String c = Utilities.doBoth(name.substring(0, name.length() - 2));  
                intent.putExtra("msg", IsThisTheRealOne.this.perhapsThis(a, b, c));  
                IsThisTheRealOne.this.sendBroadcast(intent, Manifest.permission._MSG);  
            }  
        });  
    }  
  
    static {  
        System.loadLibrary("hello-jni");  
    }  
}
```

And the **DefinitelyNotThisOne**
```java
public class DefinitelyNotThisOne extends Activity {  
    public native String computeFlag(String str, String str2);  
  
    public native String definitelyNotThis(String str, String str2);  
  
    public native String orThat(String str, String str2, String str3);  
  
    public native String perhapsThis(String str, String str2, String str3);  
  
    @Override // android.app.Activity  
    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        TextView tv = new TextView(this);  
        tv.setText("Activity - Is_this_the_real_one");  
        Button button = new Button(this);  
        button.setText("Broadcast Intent");  
        setContentView(button);  
        button.setOnClickListener(new View.OnClickListener() { // from class: com.example.application.DefinitelyNotThisOne.1  
            @Override // android.view.View.OnClickListener  
            public void onClick(View v) {  
                Intent intent = new Intent();  
                intent.setAction("com.ctf.OUTGOING_INTENT");  
                DefinitelyNotThisOne.this.getResources().getString(R.string.str1);  
                String b = Utilities.doBoth(DefinitelyNotThisOne.this.getResources().getString(R.string.test));  
                String c = Utilities.doBoth("Test");  
                intent.putExtra("msg", DefinitelyNotThisOne.this.definitelyNotThis(b, c));  
                DefinitelyNotThisOne.this.sendBroadcast(intent, Manifest.permission._MSG);  
            }  
        });  
    }  
  
    static {  
        System.loadLibrary("hello-jni");  
    }  
}
```

The **Utilities** class is for **decrypt** the **strings** in `strings.xml` resource file
```XML
<?xml version="1.0" encoding="utf-8"?>  
<resources>  
    <string name="res_0x7f030000_android_permission__msg">Msg permission for this app</string>  
    <string name="app_name">SendAnIntentApplication</string>  
    <string name="dev_name">Leetdev</string>  
    <string name="flag">Qvq lbh guvax vg jbhyq or gung rnfl?</string>  
    <string name="git_user">l33tdev42</string>  
    <string name="str1">`wTtqnVfxfLtxKB}YWFqqnXaOIck`</string>  
    <string name="str2">IIjsWa}iy</string>  
    <string name="str3">TRytfrgooq|F{i-JovFBungFk</string>  
    <string name="str4">H0l3kwjo1|+kdl^polr</string>  
    <string name="test">Test String for debugging</string>  
</resources>
```

I don't want waste my time with the **lib** native `libhello-jni.so`
So, I decide create my **own** app that send the **broadcast** to the target app.
But, before, we need change this in the **AndroidManifest.xml** file of the illintentions.apk
```XML
<permission  
        android:name="ctf.permission._MSG"  
        android:protectionLevel="signature"  
        android:description="@string/res_0x7f030000_android_permission__msg"/>  
</permission>
```
We just can rename **signature** for **normal** (or just delete the permission).

Why? Because the is protected and if we don't change this, the intent will not sent and our app will get a message like
```bash
W/BroadcastQueue(  544): Permission Denial: broadcasting Intent { act=com.ctf.INCOMING_INTENT flg=0x10 (has extras) } from illintentions.solve (pid=14364, uid=10095) requires ctf.permission._MSG due to registered receiver BroadcastFilter{265bee3c u0 ReceiverList{33c9b82f 14191 com.example.hellojni/10098/u0 remote:2317760e}}
```

So change **signature** to **normal** and save the **AndroidManifest.xml** file
Then, rebuild the **apk** with **apktool**
```bash
apktool b illintentions
```

Generate a **key**
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

Then, **sign** the apk
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore illintentions/dist/illintentions.apk alias
```

Uninstall the **original apk** from the device and install the new apk
```bash
adb install -r illintentions/dist/illintentions.apk
```

So, now we need create **our receiver**.
The files 
`MainActivity.java`
```java
package illintentions.solve;  
  
import android.app.Activity;  
import android.os.Bundle;  
  
public class MainActivity extends Activity {  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_main);  
    }  
}
```

`activity_main.xml`
```XML
<?xml version="1.0" encoding="utf-8"?>  
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"  
    android:layout_width="match_parent"  
    android:layout_height="match_parent">  
</RelativeLayout>
```

Create a **java class** for receive the intent
`Receiver.java`
```java
package illintentions.solve;  
  
import android.content.BroadcastReceiver;  
import android.content.Context;  
import android.content.Intent;  
import android.util.Log;  
  
public class Receiver extends BroadcastReceiver {  
    private static final String TAG = "Receiver";  
    @Override  
    public void onReceive(Context context, Intent intent ) {  
        String message = intent.getStringExtra("msg");  
        Log.d(TAG, "BROADCAST FOUND:");  
        Log.d(TAG, "Message: "+message);  
    }  
}
```

And the `AndroidManifest.xml` of our app looks like
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    package="illintentions.solve">  
    <uses-permission android:name="ctf.permission._MSG" />  
  
    <application  
        android:allowBackup="true"  
        android:icon="@mipmap/ic_launcher"  
        android:label="@string/app_name"  
        android:supportsRtl="true"  
        android:theme="@style/Theme.AppCompat.Light.NoActionBar">  
        <activity android:name=".MainActivity"  
            android:exported="true">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN" />  
  
                <category android:name="android.intent.category.LAUNCHER" />  
            </intent-filter>  
        </activity>  
        <receiver  android:name="Receiver"  
            android:enabled="true"  
            android:exported="true" >  
            <intent-filter>  
                <action android:name="com.ctf.OUTGOING_INTENT"/>  
            </intent-filter>  
        </receiver>  
    </application>  
</manifest>
```

So, compile our app. And wait until this is executed.
When is executed, we can call the **activities** with **adb** of the target app.
We can use `am` (activity manager) for sent a **broadcast** with adb.

Run **logcat** for get the **message logs**
```bash
adb logcat -c && adb logcat
```
And in another terminal, run
```bash
adb shell am broadcast -a com.ctf.INCOMING_INTENT -e "msg" "DefinitelyNotThisOne"
```
Press the **BROADCAST INTENT** button in the target app and:
Output: **Message: Told you so!**

Let's try with another activity
```bash
adb shell am broadcast -a com.ctf.INCOMING_INTENT -e "msg" "ThisIsTheRealOne"
```
Output: **Message: KeepTryingThisIsNotTheActivityYouAreLookingForButHereHaveSomeInternetPoints!**

So the last
```bash
adb shell am broadcast -a com.ctf.INCOMING_INTENT -e "msg" "IsThisTheRealOne"
```
Output: **Message: Congratulation!YouFoundTheRightActivityHereYouGo-CTF{IDontHaveABadjokeSorry}**

We get the flag `CTF{IDontHaveABadjokeSorry}`

I hope you found it useful (: