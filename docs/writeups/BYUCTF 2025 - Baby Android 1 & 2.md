## Baby Android 1
**Description**: If you've never reverse engineered an Android application, now is the time!! Get to it, already!! Learn how they work!!
**Download**: https://lautarovculic.com/my_files/baby-android-1.apk

![[byuctf_babyandroid1_1.png]]

Install the **APK** file using **ADB**
```bash
adb install -r baby-android-1.apk
```

We can see a message when the app is *launched*:
> Too slow!!

So, let's **analyze the source code** with **jadx**.
We can see the **`MainActivity`** class:
```java
package byuctf.downwiththefrench;

import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0486R.layout.activity_main);
        Utilities util = new Utilities(this);
        util.cleanUp();
        TextView homeText = (TextView) findViewById(C0486R.id.homeText);
        homeText.setText("Too slow!!");
    }
}
```

Notice the **`Utilities`** class, that call to `cleanUp()` method.
```java
public class Utilities {
    private Activity activity;

    public Utilities(Activity activity) {
        this.activity = activity;
    }

    public void cleanUp() {
        TextView flag = (TextView) this.activity.findViewById(C0486R.id.flagPart1);
        flag.setText("");
        TextView flag2 = (TextView) this.activity.findViewById(C0486R.id.flagPart2);
        flag2.setText("");
        TextView flag3 = (TextView) this.activity.findViewById(C0486R.id.flagPart3);
        flag3.setText("");
        TextView flag4 = (TextView) this.activity.findViewById(C0486R.id.flagPart4);
        flag4.setText("");
        TextView flag5 = (TextView) this.activity.findViewById(C0486R.id.flagPart5);
        flag5.setText("");
        TextView flag6 = (TextView) this.activity.findViewById(C0486R.id.flagPart6);
        flag6.setText("");
        TextView flag7 = (TextView) this.activity.findViewById(C0486R.id.flagPart7);
        flag7.setText("");
        TextView flag8 = (TextView) this.activity.findViewById(C0486R.id.flagPart8);
        flag8.setText("");
        TextView flag9 = (TextView) this.activity.findViewById(C0486R.id.flagPart9);
        flag9.setText("");
        TextView flag10 = (TextView) this.activity.findViewById(C0486R.id.flagPart10);
        flag10.setText("");
        TextView flag11 = (TextView) this.activity.findViewById(C0486R.id.flagPart11);
        flag11.setText("");
        TextView flag12 = (TextView) this.activity.findViewById(C0486R.id.flagPart12);
        flag12.setText("");
        TextView flag13 = (TextView) this.activity.findViewById(C0486R.id.flagPart13);
        flag13.setText("");
        TextView flag14 = (TextView) this.activity.findViewById(C0486R.id.flagPart14);
        flag14.setText("");
        TextView flag15 = (TextView) this.activity.findViewById(C0486R.id.flagPart15);
        flag15.setText("");
        TextView flag16 = (TextView) this.activity.findViewById(C0486R.id.flagPart16);
        flag16.setText("");
        TextView flag17 = (TextView) this.activity.findViewById(C0486R.id.flagPart17);
        flag17.setText("");
        TextView flag18 = (TextView) this.activity.findViewById(C0486R.id.flagPart18);
        flag18.setText("");
        TextView flag19 = (TextView) this.activity.findViewById(C0486R.id.flagPart19);
        flag19.setText("");
        TextView flag20 = (TextView) this.activity.findViewById(C0486R.id.flagPart20);
        flag20.setText("");
        TextView flag21 = (TextView) this.activity.findViewById(C0486R.id.flagPart21);
        flag21.setText("");
        TextView flag22 = (TextView) this.activity.findViewById(C0486R.id.flagPart22);
        flag22.setText("");
        TextView flag23 = (TextView) this.activity.findViewById(C0486R.id.flagPart23);
        flag23.setText("");
        TextView flag24 = (TextView) this.activity.findViewById(C0486R.id.flagPart24);
        flag24.setText("");
        TextView flag25 = (TextView) this.activity.findViewById(C0486R.id.flagPart25);
        flag25.setText("");
        TextView flag26 = (TextView) this.activity.findViewById(C0486R.id.flagPart26);
        flag26.setText("");
        TextView flag27 = (TextView) this.activity.findViewById(C0486R.id.flagPart27);
        flag27.setText("");
        TextView flag28 = (TextView) this.activity.findViewById(C0486R.id.flagPart28);
        flag28.setText("");
    }
}
```

Clearly the *flag* is *cleaned* from the `textView` when the app is launched.
We can use **frida** for **block** the `cleanUp()` function.

Just running the following script:
```javascript
Java.perform(() => {
	const Utilities = Java.use("byuctf.downwiththefrench.Utilities");

	Utilities.cleanUp.implementation = function () {
		console.log("[*] cleanUp() blocked");
		return;
	};
});
```

Then, we need **re-launch** the app using **ADB**.
Due that if we close and then, *open the app*, the *frida hooked in the process will die*.
So, we can call `MainActivity` again using **ADB** once the frida script are hooked.
Then, the app will show the flag.

![[byuctf_babyandroid1_2.png]]

Flag: **`byuctf{android_piece_0f_c4ke}`**

## Baby Android 2
**Description**: If you've never reverse engineered an Android application, now is the time!! Get to it, already!! Learn more about how they work!!
**Download**: https://lautarovculic.com/my_files/baby_android-2.apk

![[byuctf_babyandroid2_1.png]]

Install the **APK** file using **ADB**
```bash
adb install -r baby_android-2.apk
```

We can see a *flag "sanity check"* text input and button.
Let's inspect the **source code** using **jadx**.
We have a *simple code* in the **`MainActivity`** class.
```java
package byuctf.babyandroid;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes4.dex */
public class MainActivity extends AppCompatActivity {
    private EditText flag;
    private Button sanityCheck;

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(C0479R.layout.activity_main);
        this.flag = (EditText) findViewById(C0479R.id.flag_input);
        Button button = (Button) findViewById(C0479R.id.sanity_check_button);
        this.sanityCheck = button;
        button.setOnClickListener(new View.OnClickListener() { // from class: byuctf.babyandroid.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                String flagAttempt = MainActivity.this.flag.getText().toString();
                TextView banner = (TextView) MainActivity.this.findViewById(C0479R.id.banner);
                if (FlagChecker.check(flagAttempt)) {
                    banner.setText("That's the right flag!!!");
                } else {
                    banner.setText("Nope! Try again if you'd like");
                }
            }
        });
    }
}
```

But also, notice that we have the **`FlagChecker`** class.
```java
package byuctf.babyandroid;

/* loaded from: classes4.dex */
public class FlagChecker {
    public static native boolean check(String str);

    static {
        System.loadLibrary("babyandroid");
    }
}
```

The app **load a native library** called `babyandroid` (`libbabyandroid.so`).
Let's extract that using **apktool**
```bash
apktool d baby_android-2.apk
```

Inside of `baby_android-2/lib/arm64-v8a` directory we can found the `.so` file.
We will use **ghidra** for inspect the library.
Create a *new project* and *import the file*. Then, analyze.

In the *functions* side, we can observe the following function:
**`Java_byuctf_babyandroid_FlagChecker_check()`**

The code is:
```C
undefined Java_byuctf_babyandroid_FlagChecker_check
                    (_JNIEnv *param_1, undefined8 param_2, _jstring *param_3)

{
    char *pcVar1;
    long lVar2;
    int local_60;
    undefined local_34;
    basic_string<> abStack_30[24];
    long local_18;

    lVar2 = tpidr_el0;
    local_18 = *(long *)(lVar2 + 0x28);
    pcVar1 = (char *)_JNIEnv::GetStringUTFChars(param_1, param_3, (uchar *)0x0);
    std::__ndk1::basic_string<>::basic_string<>(abStack_30, pcVar1);
    lVar2 = FUN_0011dde8(abStack_30);
    if (lVar2 == 0x17) {
        for (local_60 = 0; local_60 + -0x16 == 0 || local_60 < 0x16; local_60 = local_60 + 1) {
            pcVar1 = (char *)FUN_0011de0c(local_60 + -0x16, abStack_30, (long)local_60);
            if (*pcVar1 != "bycnu)_aacGly~}tt+?=<_ML?f^i_vETk G+b{nDJrVp6=)="[(local_60 * local_60) % 0x2f]) {
                local_34 = 0;
                goto LAB_0011dcf4;
            }
        }
        local_34 = 1;
    }
    else {
        local_34 = 0;
    }
LAB_0011dcf4:
    std::__ndk1::basic_string<>::~basic_string(abStack_30);
    lVar2 = tpidr_el0;
    lVar2 = *(long *)(lVar2 + 0x28) - local_18;
    if (lVar2 == 0) {
        return local_34;
    }
    /* WARNING: Subroutine does not return */
    __stack_chk_fail(lVar2);
}
```

**Flag Checking Logic**: It appears to check the contents of the string against a **hardcoded value using a loop**. If the string **matches the expected pattern**, it sets a **local variable to true** (1), otherwise **false** (0).

Use this python code for force the *correct pattern*
```python
charset = "bycnu)_aacGly~}tt+?=<_ML?f^i_vETkG+b{nDJrVp6=)="
flag = ""

for i in range(23):
    index = (i * i) % 47
    flag += charset[index]

print(flag)
```

Flag: **`byuctf{c++_in_an_apk??}`**

I hope you found it useful (: