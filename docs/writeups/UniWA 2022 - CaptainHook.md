**Description**: Captain Hook has applied for a position in Squid Game 2022, but in order to take part into the game, he got asked to bypass the login screen of this app. Help him bypass it and he wont have the crocodile eat your hand.

**Download**: https://lautarovculic.com/my_files/Captain_Hook.apk

![[uniwa2022_captainhook1.png]]

Install the **APK** file with **ADB**
```bash
adb install -r Captain_Hook.apk
```

We can see a **login activity**. Which have `username` and `password` field with a **login button**.
Let's inspect the **source code** with **jadx**.
Looking in `AndroidManifest.xml` file, the *package name* is `com.example.captain_hook`.
And we have **two activities**:
- `MainActivity`
- `Game`

```XML
<activity
    android:name="com.example.captain_hook.Game"
    android:exported="false"/>
<activity
    android:name="com.example.captain_hook.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

We have the **java code** from `MainActivity` class:
```java
public class MainActivity extends ActivityC0491h {

    /* renamed from: com.example.captain_hook.MainActivity$a */
    public class ViewOnClickListenerC0367a implements View.OnClickListener {

        /* renamed from: b */
        public final /* synthetic */ EditText f2300b;

        /* renamed from: c */
        public final /* synthetic */ EditText f2301c;

        public ViewOnClickListenerC0367a(EditText editText, EditText editText2) {
            this.f2300b = editText;
            this.f2301c = editText2;
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (!this.f2300b.getText().toString().equals("mitroglou") || !this.f2301c.getText().toString().equals(MainActivity.this.stringFromJNI())) {
                Toast.makeText(MainActivity.this, "Wrong username or password!", 1).show();
                return;
            }
            Intent intent = new Intent(MainActivity.this, (Class<?>) Game.class);
            intent.putExtra("key", MainActivity.this.stringFromJNI());
            MainActivity.this.startActivity(intent);
        }
    }

    static {
        System.loadLibrary("captain_hook");
    }

    @Override // androidx.fragment.app.ActivityC0220q, androidx.activity.ComponentActivity, p066w.ActivityC0803f, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        View inflate = getLayoutInflater().inflate(R.layout.activity_main, (ViewGroup) null, false);
        int i2 = R.id.button;
        if (((Button) C0359b.m1359c(inflate, R.id.button)) != null) {
            if (((EditText) C0359b.m1359c(inflate, R.id.pass)) == null) {
                i2 = R.id.pass;
            } else if (((TextView) C0359b.m1359c(inflate, R.id.sample_text)) == null) {
                i2 = R.id.sample_text;
            } else if (((TextView) C0359b.m1359c(inflate, R.id.show)) == null) {
                i2 = R.id.show;
            } else if (((TextView) C0359b.m1359c(inflate, R.id.textView3)) == null) {
                i2 = R.id.textView3;
            } else {
                if (((EditText) C0359b.m1359c(inflate, R.id.uname)) != null) {
                    setContentView((ConstraintLayout) inflate);
                    EditText editText = (EditText) findViewById(R.id.uname);
                    EditText editText2 = (EditText) findViewById(R.id.pass);
                    ((Button) findViewById(R.id.button)).setOnClickListener(new ViewOnClickListenerC0367a(editText, editText2));
                    return;
                }
                i2 = R.id.uname;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(inflate.getResources().getResourceName(i2)));
    }

    public native String stringFromJNI();
}
```

In this *simple java code* we can find some functions and methods.
For example, we notice that a *native lib* are loaded that returns a **String**.

Here's the *if condition* when the *button is pressed* In this _simple java code_ we can find some functions and methods.  
For example, we notice that a _native lib_ are loaded that returns a **String**.

This will _trigger the Game method code_. And a **new `textView`** will appear with the flag if we press the button:
```java
if (!this.f2300b.getText().toString().equals("mitroglou") || !this.f2301c.getText().toString().equals(MainActivity.this.stringFromJNI())) {
    Toast.makeText(MainActivity.this, "Wrong username or password!", 1).show();
    return;
}
```

If **both the username and the password match**, an `Intent` is created:
```java
Intent intent = new Intent(MainActivity.this, (Class<?>) Game.class);
intent.putExtra("key", MainActivity.this.stringFromJNI());
MainActivity.this.startActivity(intent);
```

This **launches** the `Game` activity, which likely displays the flag:
```java
public class Game extends ActivityC0491h {
    @Override // androidx.fragment.app.ActivityC0220q, androidx.activity.ComponentActivity, p066w.ActivityC0803f, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_game);
        String stringExtra = getIntent().getStringExtra("key");
        if (stringExtra.isEmpty()) {
            return;
        }
        ((TextView) findViewById(R.id.textView3)).setText(stringExtra);
    }
}
```

The code is **obfuscated**, so to **hook into the internal logic**, we **first enumerate the internal classes**:
```javascript
Java.perform(() => {
    Java.enumerateLoadedClasses({
        onMatch(name) {
            if (name.includes("MainActivity") && name.includes("$")) {
                console.log("[*] Internal class:", name);
            }
        },
        onComplete() {
            console.log("[*] Let's hook the internal class :)");
        }
    });
});
```

Run the _frida_ command and we notice the class:
```bash
frida -U "Captain_Hook" -l hookClass.js
```
Output:
```bash
[*] Internal class: com.example.captain_hook.MainActivity$a
[*] Let's hook the internal class :)
[Redmi Note 8::Captain_Hook ]->
```

We got the class `com.example.captain_hook.MainActivity$a`.  
Now we can craft this JavaScript code that create a _new instance_ and intercept the `onClick()` method:
```javascript
Java.perform(() => {
    const MainActivity = Java.use("com.example.captain_hook.MainActivity");
    const ClickHandler = Java.use("com.example.captain_hook.MainActivity$a");

    ClickHandler.onClick.implementation = function(view) {
        // execute when login button is clicked
        this.onClick(view);

        try {
            // create a new instance of MainActivity
            const instance = MainActivity.$new();
            const flag = instance.stringFromJNI();

            console.log("[+] FLAG: " + flag);
        } catch (err) {
            console.log("[-] Error due stringFromJNI: " + err);
        }
    };
});
```
Run the frida script and then, press the **LOGIN** button.  
Output:
```bash
[Redmi Note 8::Captain_Hook ]-> [+] FLAG: UNIWA{Y0u_Ar3_my_C4pt@in}
```

Okey, we got the flag.  
Flag: **`UNIWA{Y0u_Ar3_my_C4pt@in}`**

However, *this approach doesn't trigger* the `Game` activity, since **we're calling the native method from a new instance**.
To **replicate the full behavior of the original logic** (including *launching the Game activity*), we **can modify the hook as follows**:
```javascript
Java.perform(() => {
    const MainActivity = Java.use("com.example.captain_hook.MainActivity");
    const Game = Java.use("com.example.captain_hook.Game");
    const Intent = Java.use("android.content.Intent");
    const ClickHandler = Java.use("com.example.captain_hook.MainActivity$a");

    ClickHandler.onClick.implementation = function(view) {
        // execute onClick method
        this.onClick(view);

        try {
            const activity = Java.cast(view.getContext(), MainActivity);
            const flag = activity.stringFromJNI();

            // send the Intent to Game
            const intent = Intent.$new(activity, Game.class);
            intent.putExtra("key", flag);
            activity.startActivity(intent);

            console.log("[+] Game launched: " + flag);
        } catch (err) {
            console.log("[-] Error launching Game: " + err);
        }
    };
});
```

This will *trigger the Game method code*. And a **new `textView`** will appear with the flag if we press the button!
![[uniwa2022_captainhook2.png]]

I hope you found it useful (: