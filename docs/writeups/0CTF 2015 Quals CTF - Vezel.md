**Description**
Evermars says he is good at repackaging Android applications.

For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

For download the **APK**
https://lautarovculic.com/my_files/vezel.apk

![[vezel1.png]]

Install it with **adb**
```bash
adb install -r vezel.apk
```

We can see a **text edit** and an **button**.
Let's decompile the **apk** with **apktool**
```bash
apktool d vezel.apk
```
The **package name** is `com.ctf.vezel`

Let's inspect the **source code** with **jadx**.
We just have **one** activity, that is **MainActivity**
```java
package com.ctf.vezel;  
  
import android.content.pm.PackageInfo;  
import android.content.pm.PackageManager;  
import android.content.pm.Signature;  
import android.os.Bundle;  
import android.support.v7.app.ActionBarActivity;  
import android.view.Menu;  
import android.view.MenuItem;  
import android.view.View;  
import android.widget.Button;  
import android.widget.EditText;  
import android.widget.Toast;  
import java.util.zip.ZipEntry;  
import java.util.zip.ZipFile;  
  

public class MainActivity extends ActionBarActivity {  
  

    Button f8bt;  
  

    EditText f9et;  
  

 
    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(C0175R.layout.activity_main);  
        this.f8bt = (Button) findViewById(C0175R.id.button);  
        this.f9et = (EditText) findViewById(C0175R.id.editText);  
    }  
  
    public void confirm(View v) {  
        String s = getPackageName();  
        String first = String.valueOf(getSig(s));  
        String next = getCrc();  
        String flag = "0CTF{" + first + next + "}";  
        if (flag.equals(this.f9et.getText().toString())) {  
            Toast.makeText(this, "Yes!", 0).show();  
        } else {  
            Toast.makeText(this, "0ops!", 0).show();  
        }  
    }  
  
    private int getSig(String packageName) {  
        PackageManager pm = getPackageManager();  
        try {  
            PackageInfo pi = pm.getPackageInfo(packageName, 64);  
            Signature[] s = pi.signatures;  
            int sig = s[0].toCharsString().hashCode();  
            return sig;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return 0;  
        }  
    }  
  
    private String getCrc() {  
        try {  
            ZipFile zf = new ZipFile(getApplicationContext().getPackageCodePath());  
            ZipEntry ze = zf.getEntry("classes.dex");  
            String s = String.valueOf(ze.getCrc());  
            return s;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return "";  
        }  
    }  
  

    public boolean onCreateOptionsMenu(Menu menu) {  
        getMenuInflater().inflate(C0175R.menu.menu_main, menu);  
        return true;  
    }  
  

    public boolean onOptionsItemSelected(MenuItem item) {  
        int id = item.getItemId();  
        if (id == C0175R.id.action_settings) {  
            return true;  
        }  
        return super.onOptionsItemSelected(item);  
    }  
}
```

Let's talk method by method for this code.
Let's start for **confirm**
```java
public void confirm(View v) {  
        String s = getPackageName();  
        String first = String.valueOf(getSig(s));  
        String next = getCrc();  
        String flag = "0CTF{" + first + next + "}";  
        if (flag.equals(this.f9et.getText().toString())) {  
            Toast.makeText(this, "Yes!", 0).show();  
        } else {  
            Toast.makeText(this, "0ops!", 0).show();  
        }  
    }
```

**getPackageName()**
Get the name of the package `com.ctf.vezel`
**getSig(String s)**
Get the signature or something and is parse into a string
**getCrc()**
Retrieve a string that is a CRC
**flag**
Is a build string `0CTF{<first><next>}`
And the condition, is if the **flag** is equal with the **text** that the user insert. Then, will be yes.

Now, the **getSig()** method
```java
private int getSig(String packageName) {  
        PackageManager pm = getPackageManager();  
        try {  
            PackageInfo pi = pm.getPackageInfo(packageName, 64);  
            Signature[] s = pi.signatures;  
            int sig = s[0].toCharsString().hashCode();  
            return sig;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return 0;  
        }  
    }
```

**PackageManager pm = getPackageManager()**
Get an `PackageManager` object, that is used for access to related info with the packages installed in the device.
**getPackageInfo(packageName, 64)**
Use `PackageManager` for get info from the specified package.
64, is a flag (`PackageManager.GET_SIGNATURES`) that indicates, get the signature info from package.
**Signature[] s = pi.signatures**
Get an array `Signature`that contains sign of the package.
**s[0].toCharsString().hashCode()**
Convert the `first signature` to an string and then calculate the `hashCode`. This value is used as an numeric representation of the signature.
Return the value of `hashCode`.

Then, until now, we have the following format of the flag
0CTF{`hashCode`}

Now, the **last method**
**getCrc**
```java
private String getCrc() {  
        try {  
            ZipFile zf = new ZipFile(getApplicationContext().getPackageCodePath());  
            ZipEntry ze = zf.getEntry("classes.dex");  
            String s = String.valueOf(ze.getCrc());  
            return s;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return "";  
        }  
    }
```

**ZipFile zf = new ZipFile(getApplicationContext().getPackageCodePath())**
Open the **apk** file, using the **path** of the **actual app**.
**ZipEntry ze = zf.getEntry("classes.dex")**
Search and get a entry reference to the **zip** file (apk). This file contains the bytecode.
**ze.getCrc()**
Get the CRC value from `classes.dex` file. This numeric value is used for check the file integrity.
**String s = String.valueOf(ze.getCrc())**
Convert the CRC value into an string.
Return the `CRC`value.

The flag must look like
`0CTF{<hashCode><CRC>}

So, let's start by the **CRC**
We can get the **CRC** of **classes.dex** with this **python** code
```python
import zipfile

with zipfile.ZipFile('vezel.apk', 'r') as z:
	crc = z.getinfo('classes.dex').CRC
	print(crc)
```

Or, if you prefer use frida, in **javascript**
```javascript
Java.perform(function () {
    var Context = Java.use('android.content.Context');
    var ZipFile = Java.use('java.util.zip.ZipFile');
    var ZipEntry = Java.use('java.util.zip.ZipEntry');
    
    var ActivityThread = Java.use('android.app.ActivityThread');
    var context = ActivityThread.currentApplication().getApplicationContext();
    var packageCodePath = context.getPackageCodePath();
    
    var zipFile = ZipFile.$new(packageCodePath);
    var entry = zipFile.getEntry("classes.dex");
    if (entry) {
        var crc = entry.getCrc();
        console.log("CRC:", crc);
    } else {
        console.log("Entry 'classes.dex' not found.");
    }
});
```

We get the **CRC** number: `1189242199`

Now, let's take the **sig** value.
I read many methods, indeed, I read many people doing so extensive java code.
But here are a simple way of do with **frida**
```javascript
Java.perform(function() {
    // Get a reference to the MainActivity class from the specified package
    var MainActivity = Java.use('com.ctf.vezel.MainActivity');

    // Hook the implementation of the getSig method
    MainActivity.getSig.implementation = function(packageName) {
        // Call the original getSig method and store its result
        var sig = this.getSig(packageName);

        // Print the signature hash to the console
        console.log("Signature Hash: " + sig);

        // Return the original signature hash value
        return sig;
    };
});
```

The value that we get is `-183971537`
So, the flag that we need insert is
`0CTF{-1839715371189242199}`

And the toast message will say **Yes!**

I hope you found it useful (: