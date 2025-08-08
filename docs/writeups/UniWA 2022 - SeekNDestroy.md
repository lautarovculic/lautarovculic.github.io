**Description**: James Hetfield has applied a position in Squid Game 2022, but in order to take part into the game, he was asked to bypass the login screen of this app. Help him do this and he might find you a free ticket for the concert.

**Download**: https://lautarovculic.com/my_files/Seek_N_Destroy.apk

![[uniwa2022_seekndestroy1.png]]

Install the **APK** with **ADB**
```bash
adb install -r Seek_N_Destroy.apk
```

We can see a **login** with `username` and `password`.
Let's inspect the **source code** with **jadx**.

We have **one activity**, which is **`MainActivity`**.
And the java code is:
```java
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;

    public native String stringFromJNI();

    static {
        System.loadLibrary("seek_n_destroy");
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        final EditText editText = (EditText) findViewById(C0511R.id.uname);
        final EditText editText2 = (EditText) findViewById(C0511R.id.pass);
        final TextView textView = (TextView) findViewById(C0511R.id.show);
        ((Button) findViewById(C0511R.id.button)).setOnClickListener(new View.OnClickListener() { // from class: com.example.seek_n_destroy.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (editText.getText().toString().equals("mitroglou") && MainActivity.md5(editText2.getText().toString()).equals("15eca8868ab1ae1828fff6bb7cf4b")) {
                    textView.setText(MainActivity.this.stringFromJNI());
                } else {
                    Toast.makeText(MainActivity.this, "Wrong username or password!", 1).show();
                }
            }
        });
    }

    public static String md5(String str) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(str.getBytes());
            byte[] digest = messageDigest.digest();
            StringBuffer stringBuffer = new StringBuffer();
            for (byte b : digest) {
                stringBuffer.append(Integer.toHexString(b & 255));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
    }
}
```

- The code **load** a **native lib** with the name: `libseek_n_destroy.so`
- The Button "**LOGIN**" have the following logic:
```java
((Button) findViewById(C0511R.id.button)).setOnClickListener(new View.OnClickListener() { // from class: com.example.seek_n_destroy.MainActivity.1
    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        if (editText.getText().toString().equals("mitroglou") && MainActivity.md5(editText2.getText().toString()).equals("15eca8868ab1ae1828fff6bb7cf4b")) {
            textView.setText(MainActivity.this.stringFromJNI());
        } else {
            Toast.makeText(MainActivity.this, "Wrong username or password!", 1).show();
        }
    }
});
```

Check if **username** = `mitroglou` and the **password** is the *result of MD5 hash*: `15eca8868ab1ae1828fff6bb7cf4b`.
But this **MD5** is malformed. Due *that real MD5 has 32 chars, and this one have 28*.
So we can't crack it.

We can follow **two paths** in order for *get the flag*.
Call to `stringFromJNI` hooking with frida, or *patch the APK* changing the **MD5** hash by another one that we can create.

We can do both.
In order to call `stringFromJNI` using frida, we can do it with this **JavaScript** code:
```javascript
Java.perform(() => {
    const MainActivity = Java.use('com.example.seek_n_destroy.MainActivity');

    // onclick hook (anonimate class$1)
    const LoginButtonClick = Java.use('com.example.seek_n_destroy.MainActivity$1');

    LoginButtonClick.onClick.implementation = function(view) {
        // execute
        this.onClick(view);

        // get instancia from activity
        const activity = this.this$0.value;

        // execute native method
        const flag = activity.stringFromJNI();
        console.log("[+] FLAG: " + flag);
    };
});
```

Run the app, *start frida server* on device and the in the terminal:
```bash
frida -U "Seek_N_Destroy" -l hookLogin.js
```

We got the flag!
`[Redmi Note 8::Seek_N_Destroy ]-> [+] FLAG desde JNI: UNIWA{!Se@rch_S33k_n_D3str0y!}`

Flag: **`UNIWA{!Se@rch_S33k_n_D3str0y!}`**

Now let's make it persistent changing the **MD5** value for another.
Decompile the **APK** with **apktool**
```bash
apktool d Seek_N_Destroy.apk
```

Inside of `Seek_N_Destroy/smali/com/example/seek_n_destroy` directory, we have the file with the **hardcoded MD5** value.
In `MainActivity$1.smali` search for **MD5** text.
`const-string v0, "15eca8868ab1ae1828fff6bb7cf4b"`

I create with CyberChef the following MD5:
`hola` -> `4d186321c1a7f0f354b297e8914ab240`
Change the value and save the `.smali` file.

Let's build the *new APK*!
```bash
apktool b Seek_N_Destroy
```
A new APK will be generated in `Seek_N_Destroy/dist/` directory.
Now, let's create a *keystore* with `keytool`.
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

Now, *zipalign* tool in action:
```bash
zipalign -v -p 4 Seek_N_Destroy.apk Seek_N_Destroy-aligned.apk
```

And now, *sign* the APK
```bash
apksigner sign --ks name.keystore --ks-key-alias alias --ks-pass pass:lautaro --key-pass pass:lautaro --out Seek_N_Destroy-signed.apk Seek_N_Destroy-aligned.apk
```

Uninstall the *original APK* and install the *signed version*:
```bash
adb install -r Seek_N_Destroy-signed.apk
```

Now login with the creds: `mitroglou`:`hola` and the flag **will appear**!
![[uniwa2022_seekndestroy2.png]]

I hope you found it useful (: