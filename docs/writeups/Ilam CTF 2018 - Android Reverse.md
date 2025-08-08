Download **APK**: https://lautarovculic.com/my_files/ilam_ctf_2018.zip

![[ilam_CTF1.png]]

Install the **APK** with **adb**
```bash
adb install -r app.apk
```

We can notice that the app is *totally broken*, because it's crash when we try to launch.
Decompile the app with **apktool**
```bash
apktool d app.apk
```

Let's proceed to inspect the *source code* it with **jadx** (gui version)

See that the package name is `com.example.ctf.ctf` and there are just one activity.
Which is `MainActivity` and this is the content
```java
public class MainActivity extends AppCompatActivity {  
    private static TextView textView;  
    private Button btn;  
  
    /* JADX INFO: Access modifiers changed from: protected */  
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.ComponentActivity, android.app.Activity  
    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_main);  
        textView = (TextView) findViewById(R.id.tv);  
        this.btn = (Button) findViewById(R.id.btn);  
        this.btn.setOnClickListener(new View.OnClickListener() { // from class: com.example.ctf.ctf.MainActivity.1  
            @Override // android.view.View.OnClickListener  
            public void onClick(View v) {  
                MainActivity.textView.setText(YoYo.yo(Hello.he(Yuohuo.ye(Hay.hy(Hah.ha(C0002Hist.hi("aWxhbV9jdGZfM")))))));  
            }  
        });  
        LiIl.yolo(R.id.all);  
    }  
}
```

Checking the logs with `adb logcat` there is the information extracted
```bash
12-01 14:55:50.923  1826  1826 E AndroidRuntime: java.lang.RuntimeException: Unable to start activity ComponentInfo{com.example.ctf.ctf/com.example.ctf.ctf.MainActivity}: java.lang.ArithmeticException: divide by zero
```

Inspecting the **class** `LiIl` and the `yolo` function, we can see the following code:
```
public class LiIl {  
    public static String yoli(String s) {  
        String r = BuildConfig.FLAVOR;  
        for (int i = 0; i < s.length(); i++) {  
            if (i % 3 == 0) {  
                r = r + s.charAt(i);  
            }  
            int a = s.charAt(i) / 0;  
            r = r + a;  
        }  
        return r;  
    }  
  
    public static void yolo(int a) {  
        int i = a / 0;  
    }  
}
```
The problem here is some operation that **divide by zero** as logs show.

So, let's patch the **smali code**.
Go to `smali/com/example/ctf/ctf/` and inside we have the `LiIl.smali` file.
At the end of the file, we find this
```smali
.method public static yolo(I)V
    .locals 0
    .param p0, "a"    # I

    .line 17
    div-int/lit8 p0, p0, 0x0

    .line 18
    return-void
.end method
```
Pay attention to `div-int/lit8 p0, p0, 0x0`
According to **dalvik opcodes** (https://quantiti.github.io/dalvik-opcodes/) we can change `div-int/lit8` by `add-int/lit8`
Save the file.

This will change the java code to 
```java
public static void yolo(int a) {  
        int i = a + 0;  
}
```

So, now it's time to **rebuild** the apk.
```bash
apktool b app
```

Create a keystore for certification signature process.
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

Then, use **jarsigner** for sign the apk
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore app/dist/app.apk alias
```

Uninstall the original app in the device and reinstall using adb
```bash
adb install -r app/dist/app.apk
```

I'll remove the original apk file (`rm app.apk`), move the new apk (`mv app/dist/app.apk .` and delete the folder (`rm -rf app`).
So, let's run again **apktool** for decompile the app and **jadx** for see the changes.

And if we no *run again the app, we can see the button "CLICK ME"*!
Also, notice that now the **java** code in `LiIl.yolo()` has been successful patched.

But *it crash again* if we press the button.
And in the **logs**, there say that the class **YoYo** in **function** `yo()` have a problem.
Here's the code
```java
public class YoYo {  
    public static String yo(String s) {  
        String r = BuildConfig.FLAVOR;  
        for (int i = 0; i < s.length(); i++) {  
            if (i % 3 == 0) {  
                r = r + s.charAt(i);  
            }  
            int a = s.charAt(i) / 0;  
            r = r + a;  
        }  
        return r;  
    }  
}
```

Another division by zero.
Let's move to the *new folder created* with apktool from the new apk that previously we patched. And make the new process in `smali/com/example/ctf/ctf` but now with the file `YoYo.smali`.

Open with nano and search by **div-int**.
We can see in the line `68` the code `div-int/2addr v3, v1`
Change `div` by `add` and then, make the **rebuilding** process again.

I install the **new apk**, and delete folders, and apk previously patched, just using the new one.
```bash
lautaro > ~/Desktop/CTF/MOBILE/ilam_ctf_2018 >> rm app.apk
lautaro > ~/Desktop/CTF/MOBILE/ilam_ctf_2018 >> mv app/dist/app.apk .
lautaro > ~/Desktop/CTF/MOBILE/ilam_ctf_2018 >> rm -rf app
lautaro > ~/Desktop/CTF/MOBILE/ilam_ctf_2018 >> apktool d app.apk
```
Open again **jadx** and see the code.
Also, uninstall the now old version by the new in the device.

If we press the button **CLICK ME**, now we get the following string
![[ilam_CTF2.png]]

It may be the flag?
Yes, it's the flag. **But broken**.
At the end, this was made patch twice the app for nothing, it always has been just a simple **base64** decode from the **hardcoded strings** in the **called classes**
- `MainActivity()`
- `C0002Hist()`
- `Hah()`
- `Hay()`
- `Yuohuo()`
- `Hello()`
- `YoYo()`

Which, the final **base64** string is
`aWxhbV9jdGZfMGEwOTUxOTRkYmNmNGY3OTg3NTFhYWFmZGZiXzFkYjZiMmVkMzM5ZjQ2OThiNmIzOGI1ZTdhZQ==`

Just
```bash
echo 'aWxhbV9jdGZfMGEwOTUxOTRkYmNmNGY3OTg3NTFhYWFmZGZiXzFkYjZiMmVkMzM5ZjQ2OThiNmIzOGI1ZTdhZQ==' | base64 -d
```

The flag is: **`ilam_ctf_0a095194dbcf4f798751aaafdfb_1db6b2ed339f4698b6b38b5e7ae`**
At least we practiced patching exercises (:

I hope you found it useful (: