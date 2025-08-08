**Description**: A heard there is an easy way to make money. All you have to do, is slap `1.000.000.000` times.

**Download**: https://lautarovculic.com/my_files/SlapApp-signed.apk

![[uniwa2022_slapapp1.png]]

Install the **APK** with **ADB**
```bash
adb install -r SlapApp-signed.apk
```

We can see a button that **Slap**.
We need **reach** the `1.000.000.000`

Let's analyze the **source code** with **jadx**.
We have **two activities** if we look into `AndroidManifest.xml` file:
```XML
<activity
    android:name="com.example.slapapp.ShowFlag"
    android:exported="false"/>
<activity
    android:name="com.example.slapapp.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```
- `ShowFlag`
- `MainActivity`

We just need work with `MainActivity` class.
This is the **java code**
```java
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    int counter = 0;

    static {
        System.loadLibrary("slapapp");
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        final TextView textView = (TextView) findViewById(C0511R.id.tvCounter);
        ((Button) findViewById(C0511R.id.btnSlap)).setOnClickListener(new View.OnClickListener() { // from class: com.example.slapapp.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (MainActivity.this.counter == 10) {
                    Toast.makeText(MainActivity.this, "Seriously, are you gonna click 1.000.000.000 times?.", 0).show();
                }
                if (MainActivity.this.counter == 40) {
                    Toast.makeText(MainActivity.this, "Didn't you quit already?", 0).show();
                }
                if (MainActivity.this.counter == 70) {
                    Toast.makeText(MainActivity.this, "OK, make a coffee and think about it twice.", 0).show();
                }
                if (MainActivity.this.counter == 100) {
                    Toast.makeText(MainActivity.this, "You will be slapping yourself if you keep doing this.", 0).show();
                }
                if (MainActivity.this.counter == 130) {
                    Toast.makeText(MainActivity.this, "I've already wasted too much time adding if statements. Good luck with that!", 1).show();
                }
                if (MainActivity.this.counter >= 1000000000) {
                    Toast.makeText(MainActivity.this, "Come back to get the Flag after 4 days.", 1).show();
                    new Handler().postDelayed(new Runnable() { // from class: com.example.slapapp.MainActivity.1.1
                        @Override // java.lang.Runnable
                        public void run() {
                            Intent intent = new Intent(MainActivity.this, (Class<?>) ShowFlag.class);
                            intent.putExtra("showFlag", "true");
                            MainActivity.this.startActivity(intent);
                        }
                    }, 400000000L);
                    return;
                }
                MainActivity.this.counter++;
                textView.setText(String.valueOf(MainActivity.this.counter) + "/1.000.000.000");
            }
        });
    }
}
```

We can see a series of messages as the counter advances, until we reach `1,000,000,000,000`
Then, **it will make us wait 4 days to display the flag**!

Not only that, but the counter **is not saved**! So, intentionally, we *should leave the phone on with the app in the foreground for 4 days*, **we will not do that**!

For this, we can use a simple **frida script to make our work easier**.
This script *intercept the `onClick()` method* and access to the *instance* of `MainActivity` with `this.this$0.value`.
And modify the value by `1.000.000.000` (and bypass the accumulated clicks).
Then, **send the Intent** to `ShowFlag` with the `extra` as *`True`*.
Script:
```javascript
Java.perform(() => {
    const MainActivity = Java.use('com.example.slapapp.MainActivity');
    const ShowFlag = Java.use('com.example.slapapp.ShowFlag');
    const Intent = Java.use('android.content.Intent');
    const SlapClick = Java.use('com.example.slapapp.MainActivity$1');

    SlapClick.onClick.implementation = function (view) {
        this.onClick(view); // execute original for don't break UI

        const activity = this.this$0.value;

        // set counter to 1000000000
        activity.counter.value = 1000000000;

        // trigger the ShowFlag intent (for avoid 4 days)
        const intent = Intent.$new(activity, ShowFlag.class);
        intent.putExtra("showFlag", "true");
        activity.startActivity(intent);

        console.log("[+] Slap & Flag 3:)");
    };
});
```

Launch the app, run the **frida server** in the device, and then:
```bash
frida -U "SlapApp" -l hook.js
```
Slap one time and you will see this message:
`[Redmi Note 8::SlapApp ]-> [+] Slap & Flag 3:)`

Also, the flag!
![[uniwa2022_slapapp2.png]]

Flag: **`UNIWA{sl4pp_l1k3_th1s!}`**

I hope you found it useful (: