**Description**: Someone chopped up the flag and hide it through out this challenge! Can you find all the parts and put them back together?

Download **APK**: https://lautarovculic.com/my_files/challenge1_h1-702.apk

![[h1-702_challenge1-1.png]]

Install the **apk** with **adb**
```bash
adb install -r challenge1_h1-702.apk
```
Then, decompile with **apktool**
```bash
apktool d challenge1_h1-702.apk
```

Let's inspect the **source code** with **jadx** (GUI version)
When the app is launched, we just see an **blank** activity with the text "*Reverse the apk!*"
The **package name** is `com.hackerone.mobile.challenge1`
In the **AndroidManifest.xml** we don't catch any valuable information and in the **strings.xml** file we just can find the **third part** of the flag:
```XML
<string name="part_3">part 3: analysis_</string>
```

From now, the flag look like `analysis_`
Keep reading source code.
Here's the **MainActivity** class code
```java
public class MainActivity extends AppCompatActivity {  
    public native void oneLastThing();  
  
    public native String stringFromJNI();  
  
    static {  
        System.loadLibrary("native-lib");  
    }  
  
    /* JADX INFO: Access modifiers changed from: protected */  
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.SupportActivity, android.app.Activity  
    public void onCreate(Bundle bundle) {  
        super.onCreate(bundle);  
        setContentView(R.layout.activity_main);  
        ((TextView) findViewById(R.id.sample_text)).setText("Reverse the apk!");  
        doSomething();  
    }  
  
    void doSomething() {  
        Log.d("Part 1", "The first part of your flag is: \"flag{so_much\"");  
    }  
}
```

We can see that in the `Log.d` line, is printed when **doSomething()** function is executed.
That, is called in the **onCreate** method, when we launch the activity.
So, we can read the *hardcoded string*, but, this is a good opportunity for explain about `Log`'s in Android.

- **Log.v (Verbose)**: Used for very detailed log messages that are useful for development and debugging, but are generally not needed in production.
    
- **Log.d (Debug)**: Used for debug messages. It is useful for showing information that can help developers understand the flow of the application.
    
- **Log.i (Info)**: Used for informational messages that highlight the progress of the application at a general level. It is useful for logging important events that are not errors.
    
- **Log.w (Warning)**: Used for warnings about situations that are not errors but could cause problems in the future. It indicates that something unexpected has occurred.
    
- **Log.e (Error)**: Used for logging errors that occur in the application. It is useful for identifying issues that need attention.
    
- **Log.wtf (What a Terrible Failure)**: Used for logging critical errors that indicate something has gone very wrong. It is a log level used in exceptional situations.

In this case, we have **Log.d**
How we can see the logs?
While the app is running, we can use the tool **logcat** with **adb**.
```bash
adb logcat -c && adb logcat
```
The **-c** argument is for clear the screen.
Also, we can **filter** the output with **grep** command.
```bash
adb logcat -c && adb logcat | grep Part
```

Then, relaunch the app with the **logcat** in background an look the output
```bash
10-13 02:03:41.535  6239  6239 D Part 1  : The first part of your flag is: "flag{so_much"
```

So, for now, our flag looks like:
Part 1: `flag{so_much`
Part 3: `analysis_`

Let's continue with the analysis.
We can see that there are the **FourthPart** class
```java
public class FourthPart {  
    String eight() {  
        return "w";  
    }  
  
    String five() {  
        return "_";  
    }  
  
    String four() {  
        return "h";  
    }  
  
    String one() {  
        return "m";  
    }  
  
    String seven() {  
        return "o";  
    }  
  
    String six() {  
        return "w";  
    }  
  
    String three() {  
        return "c";  
    }  
  
    String two() {  
        return "u";  
    }  
}
```

The class have some functions, that, with the name, we can conclude that the returned value is
`much_wow`

For now:
Part 1: `flag{so_much`
Part 3: `analysis_`
Part 4: `much_wow`

We can see that in the **MainActivity**, an **native-lib** are loaded.
```java
static {  
    System.loadLibrary("native-lib");  
}
```
We can found in the folder that **apktool** drop, in the lib library.
But, according our device, we can take the correct to use with **adb shell**.
Type `adb shell` for enter to file system of your emulator and go to `/data/data/com.hackerone.mobile.challenge1`
We can see that the **lib** folder is a link to `/data/app/com.hackerone.mobile.challenge1-J-ZB7q0BM4dNHY3HsXADlQ==/lib/x86` (it can vary depends of each emulator).
Go to `/data/app/com.hackerone.mobile.challenge1-J-ZB7q0BM4dNHY3HsXADlQ==/lib/x86` and you can see the file **libnative-lib.so**
Download it with **adb** to our computer
```bash
adb pull /data/app/com.hackerone.mobile.challenge1-J-ZB7q0BM4dNHY3HsXADlQ==/lib/x86/libnative-lib.so
```

And we will use **ghidra** for inspect this library.
Create an project, and import the **.so** file.
You can see in the **Functions** section, where the **MainActivity** call to
```java
public native String stringFromJNI(); 
```
Function.
And, the another function in the MainActivity code
```java
public native void oneLastThing();
```

Are also in the **.so** file
![[h1-702_challenge1-2.png]]

And we can see **where the function is referenced** clicking in the references
![[h1-702_challenge1-3.png]]

And, in the **right side**, we can see the **C** code of the function:
![[h1-702_challenge1-4.png]]

We can see the *hardcoded string* where we can find the **second part** of the flag `_static_`

Flag:
Part 1: `flag{so_much`
Part 2: `_static_`
Part 3: `analysis_`
Part 4: `much_wow`

Then, we have the function `oneLastThing()` also in the lib.
In the **Functions** tab, there are some mini-functions
![[h1-702_challenge1-5.png]]

The value that every function return is in **ASCII**, which is moving to some pointer that is returned.
The values are
`0x7d - 0x5f - 0x6c - 99 - 0x5f - 0x6e - 100 - 0x6f -  0x6f - 0x61`
You can use https://www.dcode.fr/ascii-code webpage for work with ASCII.
Clean the values with `7d 5f 6c 99 5f 6e 100 6f 6f 61` and we can notice that probably get the flag. But `99` and `100` are given us problem.
So, replace `99 -> 63` and `100 -> 64` (Hex representation)
And now, with `7d 5f 6c 63 5f 6e 64 6f 6f 61` we get this output:
`}_lc_ndooa`

After think some seconds, I match with the correct order: `_and_cool}`

Flag:
Part 1: `flag{so_much`
Part 2: `_static_`
Part 3: `analysis_`
Part 4: `much_wow`
Part 5: `_and_cool}`

Final flag:
**`flag{so_much_static_analysis_much_wow_and_cool}`**

I hope you found it useful (: