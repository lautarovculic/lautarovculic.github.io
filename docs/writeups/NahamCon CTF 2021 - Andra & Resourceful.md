## Andra
**Description**: You know what to do. :)
**Download**: https://lautarovculic.com/my_files/andra.apk

![[nahamcon2021_andra1.png]]

Install the APK file using **ADB**
```bash
adb install andra.apk
```

We can see a *simple login* activity.
Let's inspect the **source code** with **jadx**.

We can see the **credentials** of this login in the **`MainActivity`** class:
```java
final String str = "Nahamcom";
final String str2 = "pink_panther@786";
```

**Username**: `nahamcom`
**Password**: `pink_panther@786`

Then, the `com.example.hack_the_app.flag` activity will be showed with the flag.

Flag: **`flag{d9f72316dbe7ceab0db10bed1a738482`**

## Resourceful
**Description**: I built my first ever android app with authentication!
**Download**: https://lautarovculic.com/my_files/resourceful.apk

![[nahamcon2021_resourceful1.png]]

Install the APK file with **ADB**
```bash
adb install resourceful.apk
```

The application will ask us for a **password**.
Let's search in the **source code** using **jadx**.

We can found the password in the **`MainActivity`** class:
```java
public class MainActivity extends AppCompatActivity {
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C0247R.layout.activity_main);
        final EditText editText = (EditText) findViewById(C0247R.id.password);
        ((Button) findViewById(C0247R.id.submit)).setOnClickListener(new View.OnClickListener() { // from class: com.congon4tor.resourceful.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (editText.getText().toString().equals("sUp3R_S3cRe7_P4s5w0Rd")) {
                    MainActivity.this.startActivity(new Intent(MainActivity.this, (Class<?>) FlagActivity.class));
                } else {
                    Toast.makeText(MainActivity.this.getBaseContext(), "Error: Incorrect password", 1).show();
                }
            }
        });
    }
}
```

The password is `sUp3R_S3cRe7_P4s5w0Rd`.
So, we can insert the password and then. the **`FlagActivity`** will be launched.

Also, in the **`FlagActivity`** we can see how the flag is crafted:
```java
((TextView) findViewById(C0247R.id.flagTV)).setText("flag{".concat(getResources().getString(C0247R.string.md5)).concat("}"));
```

Notice that the content between `{}` is the `md5` hash stored in the **strings** resources:
```XML
<string name="md5">7eecc051f5cb3a40cd6bda40de6eeb32</string>
```

Flag: **`flag{7eecc051f5cb3a40cd6bda40de6eeb32}`**

I hope you found it useful (: