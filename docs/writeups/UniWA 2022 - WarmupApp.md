**Description**: A new game is released, but not everyone are allowed to play. Can you get the access code?

**Download**: https://lautarovculic.com/my_files/WarmupApp-signed.apk

![[uniwa2022_warmup1.png]]

Install the **APK** with **ADB**
```bash
adb install -r WarmupApp-signed.apk
```

Let's analyze the **source code** with **jadx**.
The *package name* is **`com.example.warmupapp`** and in the **`MainActivity`** class we can get the flag.
```java
public class MainActivity extends AppCompatActivity {
    private Button getBtn;
    private boolean isUser = false;

    static {
        System.loadLibrary("warmupapp");
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C0511R.layout.activity_main);
        Button button = (Button) findViewById(C0511R.id.getBtn);
        this.getBtn = button;
        button.setOnClickListener(new View.OnClickListener() { // from class: com.example.warmupapp.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (MainActivity.this.isUser) {
                    Toast.makeText(MainActivity.this, "UNIWA{w4rm1ng_my_4pp_up!!}", 0).show();
                } else {
                    Toast.makeText(MainActivity.this, "I can see your face through the camera. You are not chosen to play this game.", 0).show();
                }
            }
        });
    }
}
```

Flag: **`UNIWA{w4rm1ng_my_4pp_up!!}`**

But pay attention, that we don't "resolve" the challenge.
If we try **Get Access**, we receive the "*error*" message.
So, let's **patch the APK** with smali!

Decompile the **APK** with **apktool**
```bash
apktool d WarmupApp-signed.apk
```

Inside of `WarmupApp-signed/smali/com/example/warmupapp` directory we have the `MainActivity.smali` file.

We can see inside of **constructor** the **initialization** of the `isUser` boolean (`Z`):
```smali
.method public constructor <init>()V
    .locals 1

    .line 11
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    const/4 v0, 0x0

    .line 14
    iput-boolean v0, p0, Lcom/example/warmupapp/MainActivity;->isUser:Z

    return-void
.end method
```
We have the line `const/4 v0, 0x0`
`0x0` -> False
`0x1` -> True

Set to `0x1` and save the `MainActivity.smali` file.
Now it's **rebuild** time!
Go back until directory dropped by apktool and then, rebuild:
```bash
apktool b WarmupApp-signed
```
A new APK is generated in `WarmupApp-signed/dist/`

Now we need use `zipalign` for resources:
```bash
zipalign -v -p 4 WarmupApp-signed.apk WarmupApp-aligned.apk
```

Create a new `keystore` with `keytool`
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

To end, **sign** the APK
```bash
apksigner sign --ks name.keystore --ks-key-alias alias --ks-pass pass:lautaro --key-pass pass:lautaro --out WarmupApp-signed-2.apk WarmupApp-aligned.apk
```
Notice that `lautaro` is the password that I use for my keystore.

Uninstall the *original APK* from device and then install the `WarmupApp-signed-2.apk`.
```bash
adb install -r WarmupApp-signed-2.apk
```

Now the app are patched!
![[uniwa2022_warmup2.png]]

I hope you found it useful (: