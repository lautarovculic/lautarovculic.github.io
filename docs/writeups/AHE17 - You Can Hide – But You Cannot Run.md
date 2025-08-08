### AHE17 : Android Hacking Events 2017
For this challenge, probably we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

For download the **APK**
https://team-sik.org/wp-content/uploads/2017/06/YouCanHideButYouCannotRun.apk_.zip

![[youCanHideBYCR1.png]]

Use **apktool** for decompile the **.apk** file
```bash
apktool d YouCanHideButYouCannotRun.apk
```

And install the **.apk** with **adb**
```bash
adb install -r YouCanHideButYouCannotRun.apk
```

Launching the **app** we can see that we have a text that talk about **encryption** and **a button**. That say **Start** to **Running** if we press it.

Let's **load** the **.apk** to **jadx** for see the **source code**.
We have the following package:
`hackchallenge.ahe17.teamsik.org.romanempire`
And the **AndroidManifest.xml** file:
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    android:versionCode="1"  
    android:versionName="1.0"  
    package="hackchallenge.ahe17.teamsik.org.romanempire"  
    platformBuildVersionCode="25"  
    platformBuildVersionName="7.1.1">  
    <uses-sdk  
        android:minSdkVersion="15"  
        android:targetSdkVersion="25"/>  
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>  
    <application  
        android:theme="@style/AppTheme"  
        android:label="@string/app_name"  
        android:icon="@mipmap/ic_launcher"  
        android:debuggable="true"  
        android:allowBackup="true"  
        android:supportsRtl="true"  
        android:roundIcon="@mipmap/ic_launcher_round">  
        <activity android:name="hackchallenge.ahe17.teamsik.org.romanempire.MainActivity">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
    </application>  
</manifest>
```

Look the **permission**
```XML
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
```
Why this app need **write** in the storage?

And, notice that in the **AndroidManifest.xml** file we have a **MainActivity** with this content:
```java
package hackchallenge.ahe17.teamsik.org.romanempire;  
  
import android.os.Bundle;  
import android.support.v7.app.AppCompatActivity;  
import android.view.View;  
import android.widget.Button;  
   
public class MainActivity extends AppCompatActivity {  
    Button start;  
    boolean startedflag = false;  
  
    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_main);  
        initialize();  
    }  
  
    private void initialize() {  
        this.start = (Button) findViewById(R.id.start);  
        this.start.setOnClickListener(new View.OnClickListener() { 
            public void onClick(View v) {  
                if (!MainActivity.this.startedflag) {  
                    MainActivity.this.startedflag = true;  
                    MainActivity.this.start.setText("Running...");  
                    MakeThreads.startWrites(MainActivity.this);  
                }  
            }  
        });  
    }  
}
```

In the **MainActivity**, we can see in **initialize()** method the **MakeThreads** class.
That have this content:
```java
public class MakeThreads {  
    private static ArrayList<Thread> threads;  
  
    public static void startWrites(Activity activity) {  
        File directory = new File(activity.getApplicationInfo().dataDir + "/Rome");  
        directory.mkdirs();  
        File scroll = new File(directory, "scroll.txt");  
        try {  
            RandomAccessFile raf = new RandomAccessFile(scroll, "rw");  
            FileOutputStream f = new FileOutputStream(scroll);  
            new PrintWriter(f);  
            threads = new ArrayList<>();  
            threads.add(new X4bc86a15e3dc7ff7dca5240422059c40ca55f084(raf)); 
            [---------]
            [---------]
            [---------]
            [---------]
            threads.add(new X1b629eed17073f7c9d6b318b77ab05bb453692f4(raf));  
        } catch (FileNotFoundException e) {  
            e.printStackTrace();  
        } catch (IOException e2) {  
            e2.printStackTrace();  
        }  
        Iterator<Thread> it = threads.iterator();  
        while (it.hasNext()) {  
            Thread t = it.next();  
            t.start();  
        }  
    }  
  
    public static void stopWrites(Activity activity) {  
        Iterator<Thread> it = threads.iterator();  
        while (it.hasNext()) {  
            Thread t = it.next();  
            t.interrupt();  
        }  
    }  
}
```

We can see that imports the **classes** like
```java
public class X04c3eb5ce6c5e299ad93dac871bbbed16da09e21 extends Thread {  
    RandomAccessFile a;  
    long sleepTillTime = 41000;  
    char c = 'l';  
    int timetoSleep = 250;  
  
    public X04c3eb5ce6c5e299ad93dac871bbbed16da09e21(RandomAccessFile a) {  
        this.a = a;  
    }  
  
    public void run() {  
        try {  
            Thread.sleep(this.sleepTillTime);  
        } catch (InterruptedException e) {  
            e.printStackTrace();  
        }  
        try {  
            this.a.seek(0L);  
            this.a.writeChar(this.c);  
            this.a.writeChar(10);  
        } catch (IOException e2) {  
            e2.printStackTrace();  
        }  
    }  
}
```

Which we have the **char c** variable and **sleepTillTime**.
This will create the **scroll.txt** file in
`/data/data/hackchallenge.ahe17.teamsik.org.romanempire/Rome`
But, **every char** overwrite the previous char.

I try, but without successful
```java
RandomAccessFile raf = new RandomAccessFile(scroll, "rw");  
```
Change via **smali** code to **"rwd"** for write **as append** char by char. But don't work.
And, the **chars** are printed and **saved** **Randomly**. Then, this don't make sense, but I mention because this can work (if random isn't present)

Then, probably we need use frida for **hook** the function.
Here's a **javascript** script that use **java.io.RandomAccessFile**
```javascript
Java.perform(function() {
    // Initialize an empty array to collect characters written to the file.
    var flagArray = [];
    
    // Get a reference to the RandomAccessFile class.
    var RandomAccessFile = Java.use('java.io.RandomAccessFile');
    
    // Intercept the seek method of RandomAccessFile.
    RandomAccessFile.seek.implementation = function(pos) {
        // If the position is 0, set the skip flag to false.
        if (pos === 0) {
            this.skip = false;
        }
        // Call the original seek method and return its result.
        return this.seek.call(this, pos);
    };

    // Intercept the writeChar method of RandomAccessFile.
    RandomAccessFile.writeChar.implementation = function(c) {
        // If the skip flag is true or the character is a newline (10), send the current accumulated flagArray.
        if (this.skip || c === 10) {
            send("PARTIAL:" + flagArray.join(""));
        } else {
            // Convert the character code to a character and add it to flagArray.
            flagArray.push(String.fromCharCode(c));
            // Send the character as a SYM message.
            send("SYM:" + String.fromCharCode(c));
        }
        // Call the original writeChar method and return its result.
        return this.writeChar.call(this, c);
    };

});
```

Then, **run** frida server in your device and get the **PID** of the app (**Button must be in start condition**)
With the **app running**, run in your terminal
```bash
frida-ps -Uai
```

Copy the **PID** of **RomanEmpire** app.
Then, attach the **script** into the app with
```bash
frida -U -p <PID> -l script.js
```

Now **press the button** and when start running, you will see the code intercepting the functions.
Just wait to the end until you see this output
```bash
message: {'type': 'send', 'payload': 'PARTIAL:Aol jsvjrdvyr ohz ybzalk Puav h zapmm tvklyu hya zahabl, Whpualk if uhabyl, svhaolk if aol Thzzlz, huk svclk if aol mld. Aol nlhyz zjylht pu h mhpslk ylcpchs: HOL17{IlaalyJyfwaZ4m3vyKpl}!'} data: None
```

In clean
`Aol jsvjrdvyr ohz ybzalk Puav h zapmm tvklyu hya zahabl, Whpualk if uhabyl, svhaolk if aol Thzzlz, huk svclk if aol mld. Aol nlhyz zjylht pu h mhpslk ylcpchs: HOL17{IlaalyJyfwaZ4m3vyKpl}!`

This is a Caesar's Cipher text, we can rote this in any online tool.
But here's a **python** script
```python
def caesar_cipher(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            start = ord('a') if char.islower() else ord('A')
            # Crypt
            new_char = chr(start + (ord(char) - start + shift_amount) % 26)
            result.append(new_char)
        else:
            # Don't encrypt non-alphabetic chars
            result.append(char)
    return ''.join(result)

def main():
    text = input("Enter the text to encrypt: ")

    # ROT TEXT FROM 1 TO 25 TIMES
    for shift in range(1, 26):
        encrypted_text = caesar_cipher(text, shift)
        print(f"\n[+] Shift [{shift}]: {encrypted_text}")

if __name__ == "__main__":
    main()
```

Just paste the text and if you see the **19** ROT, you can found the final string with the flag.

`The clockwork has rusted Into a stiff modern art statue, Painted by nature, loathed by the Masses, and loved by the few. The gears scream in a failed revival: AHE17{BetterCryptS4f3orDie}!`

Flag: **AHE17{BetterCryptS4f3orDie}**

I hope you found it useful (: