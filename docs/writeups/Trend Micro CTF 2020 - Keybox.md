**Description**: The flag file is built into this Android application APK file.
The flag is encrypted using five keys.
Below is shown the status of each of the five keys. Red is locked, green is unlocked.
The challenge is to decrypt each of these keys so that you can decrypt the flag. Tap on each key to retrieve hints to help you to decrypt that key.

**Download APK**: https://lautarovculic.com/my_files/Keybox.apk

![[keyboxTrendMicro1.png]]

## Static Analysis

Let's install the APK file with **ADB**
```bash
adb install -r Keybox.apk
```
Also, decompile it using **apktool**
```bash
apktool d Keybox.apk
```

Move to **jadx** for inspect the **source code**.
Here's the **`AndroidManifest.xml`** file
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    android:versionCode="1"  
    android:versionName="1.0"  
    android:compileSdkVersion="28"  
    android:compileSdkVersionCodename="9"  
    package="com.trendmicro.keybox"  
    platformBuildVersionCode="28"  
    platformBuildVersionName="9">  
    <uses-sdk  
        android:minSdkVersion="27"  
        android:targetSdkVersion="28"/>  
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>  
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>  
    <uses-permission android:name="android.permission.PROCESS_OUTGOING_CALLS"/>  
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>  
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>  
    <uses-permission android:name="android.permission.READ_SMS"/>  
    <uses-permission android:name="android.permission.SEND_SMS"/>  
    <application  
        android:theme="@style/AppTheme"  
        android:label="@string/app_name"  
        android:icon="@mipmap/ic_redkey"  
        android:debuggable="true"  
        android:launchMode="singleInstance"  
        android:allowBackup="true"  
        android:supportsRtl="true"  
        android:extractNativeLibs="false"  
        android:roundIcon="@mipmap/ic_redkey_round"  
        android:appComponentFactory="android.support.v4.app.CoreComponentFactory">  
        <activity  
            android:theme="@style/AppTheme.NoActionBar"  
            android:label="@string/title_activity_flag"  
            android:name="com.trendmicro.keybox.FlagActivity"  
            android:exported="true"  
            android:parentActivityName="com.trendmicro.keybox.KeyboxMainActivity">  
            <intent-filter>  
                <action android:name="com.trendmicro.keybox.UNLOCK_FLAG"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
        <activity  
            android:theme="@style/AppTheme.NoActionBar"  
            android:label="@string/title_activity_key4_hint"  
            android:name="com.trendmicro.keybox.KEY4HintActivity"  
            android:exported="true"  
            android:parentActivityName="com.trendmicro.keybox.KeyboxMainActivity">  
            <intent-filter>  
                <action android:name="com.trendmicro.keybox.UNLOCK_HINT"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
            <meta-data  
                android:name="android.support.PARENT_ACTIVITY"  
                android:value="com.trendmicro.keybox.KeyboxMainActivity"/>  
        </activity>  
        <activity  
            android:theme="@style/AppTheme.NoActionBar"  
            android:label="@string/title_activity_key3_hint"  
            android:name="com.trendmicro.keybox.KEY3HintActivity"  
            android:exported="true"  
            android:parentActivityName="com.trendmicro.keybox.KeyboxMainActivity">  
            <intent-filter>  
                <action android:name="com.trendmicro.keybox.UNLOCK_HINT"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
            <meta-data  
                android:name="android.support.PARENT_ACTIVITY"  
                android:value="com.trendmicro.keybox.KeyboxMainActivity"/>  
        </activity>  
        <receiver  
            android:name="com.trendmicro.keybox.Unlocker"  
            android:enabled="true"  
            android:exported="true">  
            <intent-filter>  
                <action android:name="android.provider.Telephony.SECRET_CODE"/>  
                <data  
                    android:scheme="android_secret_code"  
                    android:host="8736364276"/>  
                <data  
                    android:scheme="android_secret_code"  
                    android:host="8736364275"/>  
            </intent-filter>  
            <intent-filter>  
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>  
                <action android:name="android.provider.Telephony.SMS_SENT"/>  
            </intent-filter>  
            <intent-filter>  
                <action android:name="android.intent.action.PHONE_STATE"/>  
            </intent-filter>  
            <intent-filter>  
                <action android:name="android.intent.action.CALL"/>  
            </intent-filter>  
        </receiver>  
        <activity  
            android:theme="@style/AppTheme.NoActionBar"  
            android:label="@string/title_activity_key2_hint"  
            android:name="com.trendmicro.keybox.KEY2HintActivity"  
            android:exported="true"  
            android:parentActivityName="com.trendmicro.keybox.KeyboxMainActivity">  
            <intent-filter>  
                <action android:name="com.trendmicro.keybox.UNLOCK_HINT"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
            <meta-data  
                android:name="android.support.PARENT_ACTIVITY"  
                android:value="com.trendmicro.keybox.KeyboxMainActivity"/>  
        </activity>  
        <activity  
            android:theme="@style/AppTheme.NoActionBar"  
            android:label="@string/title_activity_key1_hint"  
            android:name="com.trendmicro.keybox.KEY1HintActivity"  
            android:exported="true"  
            android:hint="Unlocking the hints requires sending the appropriate intent : adb shell am start-activity -a com.trendmicro.keybox.UNLOCK_HINT -n com.trendmicro.keybox/.KEY1HintActivity -e hintkey1 $PASSWORD"  
            android:parentActivityName="com.trendmicro.keybox.KeyboxMainActivity">  
            <intent-filter>  
                <action android:name="com.trendmicro.keybox.UNLOCK_HINT"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
            <meta-data  
                android:name="android.support.PARENT_ACTIVITY"  
                android:value="com.trendmicro.keybox.KeyboxMainActivity"/>  
        </activity>  
        <activity  
            android:theme="@style/AppTheme.NoActionBar"  
            android:label="@string/title_activity_key0_hint"  
            android:name="com.trendmicro.keybox.KEY0HintActivity"  
            android:exported="true"  
            android:parentActivityName="com.trendmicro.keybox.KeyboxMainActivity">  
            <intent-filter>  
                <action android:name="com.trendmicro.keybox.UNLOCK_HINT"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
        <activity android:name="com.trendmicro.keybox.KeyboxMainActivity">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
    </application>  
</manifest>
```

If we go to **Key 0**, we can see that is **auto decrypted** and enabled.
Also, there are information about the challenge.

### Key 1

Let's do the **Key 1**.
If we *press the button*, we can see that the **Hint is locked**.
But we can see in the `AndroidManifest.xml` file the content of the hint:
```XML
<activity
    android:theme="@style/AppTheme.NoActionBar"
    android:label="@string/title_activity_key1_hint"
    android:name="com.trendmicro.keybox.KEY1HintActivity"
    android:exported="true"
    android:hint="Unlocking the hints requires sending the appropriate intent : adb shell am start-activity -a com.trendmicro.keybox.UNLOCK_HINT -n com.trendmicro.keybox/.KEY1HintActivity -e hintkey1 $PASSWORD"
    android:parentActivityName="com.trendmicro.keybox.KeyboxMainActivity">
    <intent-filter>
        <action android:name="com.trendmicro.keybox.UNLOCK_HINT"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <meta-data
        android:name="android.support.PARENT_ACTIVITY"
        android:value="com.trendmicro.keybox.KeyboxMainActivity"/>
</activity>
```

Here's the content of **java code** for Key 1
```java
public class KEY1HintActivity extends AppCompatActivity {
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.SupportActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_key1_hint);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        Singleton singleton = Singleton.getInstance();
        TextView textView = (TextView) findViewById(R.id.hintTextView);
        TextView titleView = (TextView) findViewById(R.id.hintTitleView);
        Intent intent = getIntent();
        String key = intent.getStringExtra("hintkey1");
        if (key != null) {
            singleton.hintkey1 = key;
        }
        HippoLoader loader = new HippoLoader(1);
        loader.setAndroidContext(this);
        loader.setTextView(textView);
        loader.setTitleView(titleView);
        if (!loader.entrypoint()) {
            loader.execute("log_ciphertext_js", true);
        }
    }
}
```

The activities looks for intent with **`hintkey0-4`** as extra.
We can see the **Singleton object**, the java code is:
```java
private Singleton() {
    try {
        ContextFactoryFactory contextFactoryFactory = new ContextFactoryFactory();
        this.factory = contextFactoryFactory;
        this.hintkey0 = contextFactoryFactory.CreateKey(0);
        this.hintkeymain = this.factory.CreateKey(1);
        this.key4_box = new String[]{"", "", ""};
        this.box_index = 0;
    } catch (Exception e) {
    }
}
[...]
[...]
[...]
```

Let's inspect the `ContextFactoryFactory`.
```java
public class ContextFactoryFactory {
    public String contextURL = new String("content://sms");
    public URI javauri = new URI(this.contextURL);
    private String hintkey0 = new String("TrendMicro");

    public Object ContextFactoryFactory(Object o) throws Exception {
        return new ContextFactoryFactory();
    }

    public String resolverFactory() {
        return this.contextURL;
    }

    public byte[] PreinitializedSBox() {
        byte[] S = {64, -48, 114, 0, -20, 108, -30, 85, -102, -101, 105, 71, 123, -69, 50, 78, -80, -103, 24, 106, 69, -124, -23, 101, -40, 125, -65, 111, -51, -76, 121, 44, 53, 33, -70, 43, -31, 75, -79, 118, -24, -109, 4, 77, 60, ByteCode.T_LONG, 86, 65, 8, -8, 109, -11, 10, 3, -75, -123, 40, -94, 76, -47, 56, 7, 112, 92, 80, 9, -108, -61, -14, -106, -37, -127, 81, -29, 117, -45, -64, 51, -81, -107, -110, -71, 35, -22, 59, 82, 100, -86, 14, 90, -33, 95, -41, -121, 98, -16, Byte.MAX_VALUE, 39, 29, -52, 25, -122, -5, 119, -7, -6, -46, 57, 120, -67, -39, -63, 17, -125, -85, -42, -82, 116, 104, 32, -74, 41, 89, 94, 23, 115, -100, Byte.MIN_VALUE, -44, 46, -113, -84, -117, -1, -36, -35, -91, 99, 91, -25, -17, -10, -72, 66, -66, -53, -93, -90, -120, -9, 49, -27, 1, -87, -77, -89, -105, 68, -32, 45, -95, -88, 22, -98, 27, -43, -112, -92, -38, -114, -21, 42, 107, 28, 73, 124, 36, -15, 19, -62, 79, -60, 47, -126, 20, -55, 58, -97, 110, 63, -50, 2, 15, 88, 12, -59, 67, -78, 102, 74, 126, -57, -19, -34, 70, 83, -49, 16, 34, -13, -111, 103, -56, 93, 61, 37, 113, -26, -73, -54, -99, -104, -83, 21, 84, -119, 62, -3, -116, -96, -12, 87, 97, 5, -18, 122, 48, 38, -68, 18, -118, 54, 6, 72, 26, 31, -58, -4, -115, 52, 55, 13, -2, 30, -28, 96};
        return S;
    }

    public String CreateKey(int keynumber) {
        return this.hintkey0;
    }
}
```

Pay attention in
```java
public String CreateKey(int keynumber) {
    return this.hintkey0;
}
```
The value is `TrendMicro`.
Remember the hint in **Key 0**. This is probably the **password** for set the **intent**.

```bash
adb shell am start -a com.trendmicro.keybox.UNLOCK_HINT -n com.trendmicro.keybox/.KEY1HintActivity -e hintkey1 "TrendMicro"
```
Now we can see the **Key 1** hint:
```text
Good job figuring out the password to the Key One hints!
As you are aware, the password you used was 'TrendMicro'.
Here is a hint about decrypting flagkey1.enc:
To unlock Key 1, you must call Trend Micro
```

In my mind, this is difficult due to this challenge was made in 2020, and we are in 2025.
So, the *phone number was changed*.
But using some **OSINT techniques** I found the profile of an *TrendMicro*:
https://www.sendall.co/organization-lookup/Trend%20Micro/0361b2fb-1a84-4514-a92e-df5ba304484e

Where says that the phone number is: `+81353343618`
Let's understand how the *Key 1* is decrypted.
We can see the **`Unlocker`** class, we see the line:
`singleton.flagkey1_key = data2.replaceAll("[^\\d.]", "");`
This apply a **regex** expression of the number phone, leaving the value `81353343618`.
So, just delete all non-number characters.
```java
if (action.equals("android.intent.action.PHONE_STATE")) {
    // Handle incoming number
    String incomingNumber = intent.getStringExtra("incoming_number");
    if (incomingNumber != null) {
        singleton.flagkey1_key = incomingNumber.replaceAll("[^\\d.]", "");
    }

    // Check phone state
    Bundle bundle = intent.getExtras();
    if (bundle != null) {
        for (String key : bundle.keySet()) {
            Object value = bundle.get(key);
            if (key.equals("state") && value.toString().equals("IDLE")) {
                // Launch main activity when phone returns to idle state
                Intent mainActivityIntent = new Intent();
                mainActivityIntent.setClassName(
                    BuildConfig.APPLICATION_ID, 
                    "com.trendmicro.keybox.KeyboxMainActivity"
                );
                mainActivityIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(mainActivityIntent);
            }
        }
    }
}
```

So we can decrypt the key with this python code:
```python
from arc4 import ARC4

encryptedKey = open("assets/key_1/key_1.enc",'rb').read()
value = ARC4(b'81353343618')

print("The Key 1 is: " + value.encrypt(encryptedKey).decode())
```
Output:
`The Key 1 is:` **KEY1-1047645455**

Until now we have:
**Key 0** -> **`KEY0-7135446200`**
**Key 1** -> **`KEY1-1047645455`**

### Key 2

Let's start with **Key 2**!
Open the Hint activity with
```bash
adb shell am start -a com.trendmicro.keybox.UNLOCK_HINT -n com.trendmicro.keybox/.KEY2HintActivity -e hintkey2 "TrendMicro"
```

The content of the hint is:
```text
To unlock KEY2, send the secret code
```
We can see in the `AndroidManifest.xml` the **Broadcast Receiver**
```XML
<receiver
    android:name="com.trendmicro.keybox.Unlocker"
    android:enabled="true"
    android:exported="true">
    
    <intent-filter>
        <action android:name="android.provider.Telephony.SECRET_CODE"/>
        <data
            android:scheme="android_secret_code"
            android:host="8736364276"/>
        <data
            android:scheme="android_secret_code"
            android:host="8736364275"/>
    </intent-filter>
    
    <intent-filter>
        <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
        <action android:name="android.provider.Telephony.SMS_SENT"/>
    </intent-filter>
    
    <intent-filter>
        <action android:name="android.intent.action.PHONE_STATE"/>
    </intent-filter>
    
    <intent-filter>
        <action android:name="android.intent.action.CALL"/>
    </intent-filter>
</receiver>
```

This will send to **Unlocker** class again, but in this case, for Key 2:
```java
if (action.equals("android.provider.Telephony.SECRET_CODE")) {
    // Get the secret code that was dialed
    String secretCode = intent.getData().getHost();
    
    // Handle special code 8736364276
    if (secretCode.equals("8736364276")) {
        Singleton.getInstance(true);  // Initialize singleton with special flag
    } 
    // Store other valid codes
    else {
        singleton.flagkey2_key = secretCode;  // Store for later verification
    }
    
    // Launch main activity regardless of which code was entered
    Intent mainActivityIntent = new Intent();
    mainActivityIntent.setClassName(
        BuildConfig.APPLICATION_ID, 
        "com.trendmicro.keybox.KeyboxMainActivity"
    );
    mainActivityIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);  // 268435456
    context.startActivity(mainActivityIntent);
    
    return;  // Exit after handling secret code
}
```

So, the **correct code is** `8736364275`.
For this:
```java
else {
        singleton.flagkey2_key = secretCode;  // Store for later verification
    }
```
The code is like **Key 1**, but changing the value by `8736364275`

```python
from arc4 import ARC4

encryptedKey = open("assets/key_2/key_2.enc",'rb').read()
value = ARC4(b'8736364275')

print("The Key 2 is: " + value.encrypt(encryptedKey).decode())
```
Output:
`The Key 2 is:` **KEY2-9517232028**

Until now we have:
**Key 0** -> **`KEY0-7135446200`**
**Key 1** -> **`KEY1-1047645455`**
**Key 2** -> **`KEY2-9517232028`**

### Key 3

The hint for this key is
`Unlock KEY3 with the right text message`

We found references for Key 3 in **Observer** class:
```java
public class Observer extends ContentObserver {
    private Context context;
    private Cursor cursor;
    private ContextFactoryFactory factory;
    private String message;
    private final Singleton singleton;
    private Uri uri;

    public Observer(Handler handler) {
        super(handler);
        this.singleton = Singleton.getInstance();
    }

    @Override
    public void onChange(boolean selfChange) {
        if (this.context == null) {
            return;
        }

        // Initialize factory and URI
        try {
            ContextFactoryFactory contextFactoryFactory = new ContextFactoryFactory();
            this.factory = contextFactoryFactory;
            this.uri = Uri.parse(contextFactoryFactory.resolverFactory());
        } catch (Exception e) {
            // Silent catch
        }

        super.onChange(selfChange);

        try {
            // Query SMS content provider
            Cursor query = this.context.getContentResolver().query(
                this.uri, 
                null, 
                null, 
                null, 
                null
            );
            this.cursor = query;

            if (query != null && query.moveToFirst()) {
                processCursorResults();
            }

            if (this.cursor != null) {
                this.cursor.close();
            }
        } catch (Exception e) {
            Log.d("TMCTF", "SMS observer error: " + e.getLocalizedMessage());
        }
    }

    private void processCursorResults() {
        for (int i = 0; i < this.cursor.getColumnCount(); i++) {
            String columnName = this.cursor.getColumnName(i);
            String columnValue = this.cursor.getString(i);

            // Debug logging
            String.format("%s == %s", columnName, columnValue);

            if (isValidSmsMessage(columnName, columnValue)) {
                handleValidMessage(columnValue);
            }

            this.message = ""; // Reset message
        }
    }

    private boolean isValidSmsMessage(String columnName, String columnValue) {
        return columnValue != null 
            && columnName != null 
            && columnValue.equals(columnName)
            && this.cursor.getInt(this.cursor.getColumnIndex("type")) == 1;
    }

    private void handleValidMessage(String messageContent) {
        this.message = messageContent;
        this.singleton.flagkey3_key = messageContent;
        
        // Launch main activity
        Intent mainIntent = new Intent();
        mainIntent.setClassName(
            BuildConfig.APPLICATION_ID, 
            "com.trendmicro.keybox.KeyboxMainActivity"
        );
        mainIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK); // 268435456
        this.context.startActivity(mainIntent);
    }

    public void setContext(Context context) {
        this.context = context;
    }
}
```

Also previously we was seen an Content Resolver in
```java
public class ContextFactoryFactory {  
    public String contextURL = new String("content://sms");  
    public URI javauri = new URI(this.contextURL);
```

Pay attention in
```java
private boolean isValidSmsMessage(String columnName, String columnValue) {
        return columnValue != null 
            && columnName != null 
            && columnValue.equals(columnName)
            && this.cursor.getInt(this.cursor.getColumnIndex("type")) == 1;
    }
```
This probably are taking a value from some column name, and the name as value.
As **type** is the "second" (due to ` == 1` is the second value in Index context).
According to **Android Documentation**
https://developer.android.com/reference/android/provider/Telephony.TextBasedSmsColumns

We can see that the **body** column is the second one.
So, with this python script:
```python
from arc4 import ARC4

encryptedKey = open("assets/key_3/key_3.enc",'rb').read()
value = ARC4(b'body')

print("The Key 3 is: " + value.encrypt(encryptedKey).decode())
```
Output:
`The Key 3 is:` **KEY3-2510789910**

Until now we have:
**Key 0** -> **`KEY0-7135446200`**
**Key 1** -> **`KEY1-1047645455`**
**Key 2** -> **`KEY2-9517232028`**
**Key 3** -> **`KEY3-2510789910`**

### Key 4

The hint for this key is:
`Visit the headquarters to unlock Key 4`

You can get the **3 headquarters** from the Official Trend Micro pages:
https://www.trendmicro.com/en_us/contact.html

In this case we have
- **Japan**
- **Canada**
- **USA**

![[keyboxTrendMicro2.png]]

Set the location and the key will be prompted.
**Key 4** -> **`KEY4-4721296569`**

Until now we have:
**Key 0** -> **`KEY0-7135446200`**
**Key 1** -> **`KEY1-1047645455`**
**Key 2** -> **`KEY2-9517232028`**
**Key 3** -> **`KEY3-2510789910`**
**Key 4** -> **`KEY4-4721296569`**

### The Flag

We have the **Flag Activity**
```java
public class FlagActivity extends AppCompatActivity {  
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.SupportActivity, android.app.Activity  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_flag);  
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);  
        setSupportActionBar(toolbar);  
        Singleton.getInstance();  
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);  
        Intent intent = getIntent();  
        String key0 = intent.getStringExtra("key0");  
        String key1 = intent.getStringExtra("key1");  
        String key2 = intent.getStringExtra("key2");  
        String key3 = intent.getStringExtra("key3");  
        String key4 = intent.getStringExtra("key4");  
        TextView textView = (TextView) findViewById(R.id.hintTextView);  
        TextView titleView = (TextView) findViewById(R.id.hintTitleView);  
        try {
[...]
[...]
[...]
```

![[keyboxTrendMicro3.png]]

The flag is:
**`TMCTF{pzDbkfWGcE}`**

I hope you found it useful (: