**Download**: https://lautarovculic.com/my_files/google2020reverse.apk

![[googleCTF2020sandbox1.png]]

Install the APK with **ADB**
```bash
adb install -r google2020reverse.apk
```

Let's inspect the **source code** with **jadx**.
We can see that jadx doesn't work.
So move to **dex2jar** tool.
```bash
d2j-dex2jar google2020reverse.apk
```

The `MainActivity` is called `ő`.
The code is malformed, that why we can't decompile the code and then, read it.

The constructor and `onCreate()` are obfuscated with **invalid try/catch** (such as `catch I`, which is invalid because int is **not a Throwable**).

So we need **patch the apk** in the *smali code*.
First, we need decompile with **apktool**
```bash
apktool d google2020reverse.apk
```

So, what is broken?
The `catch I` and `catch J` are not **child classes of Throwable**.
So we need go to
`/smali/com/google/ctf/sandbox/ő.smali`
And edit with nano, looking for *invalid catches* and then, delete.
Delete any `.catch` lines that use primitive types, such as:
`.catch I` → int
`.catch J` → long
`.catch Z`, `.catch F`, etc.

Stay only with `.catches` that have `L<class>;`, such as `Ljava/lang/Exception;`.
Also, you must fix the `.catch` in `ő$1.smali`

I deleted in `ő$1.smali`
`.catch I {:try_start_0 .. :try_end_0} :catch_1`

And in `ő$1.smali`
`.catch J {:try_start_0 .. :try_end_0} :catch_0`

So now we just need *rebuild the APK*
```bash
apktool b google2020reverse -o google2020fixed.apk
```

And now we can use **dj2** and **jd-gui**
```bash
d2j-dex2jar google2020fixed.apk
```

```bash
jd-gui google2020fixed-dex2jar.jar
```

Now we can see the `ő` class fully.
In the end of the code, we see that here's the validation:
```java
this();
i = arrayOfObject.length;
b = 0;
} catch (Exception|Error exception) {}
while (b < i) {
    exception.append(((Character)arrayOfObject[b]).charValue());
    b++;
} 
if (editText.getText().toString().equals(exception.toString())) {
    textView.setText("");
} else {
    textView.setText("❌");
} 
}
});
```

And we see that the flag have a length of `48`
`arrayOfObject[48] = Integer.valueOf(63);`

We see in the `R` class this kind of encoding:
```java
public final class R {
    public static long[] (long paramLong1, long paramLong2) {
        if (paramLong1 == 0L)
            return new long[] { 0L, 1L }; 
        long[] arrayOfLong = (paramLong2 % paramLong1, paramLong1);
        return new long[] { arrayOfLong[1] - paramLong2 / paramLong1 * arrayOfLong[0], arrayOfLong[0] };
    }
}
```

But anyway, I will use **jadx** for a better reading.
`jadx-gui google2020fixed-dex2jar.jar`

No we can see the **full code** more clearly:
```java
public class ActivityC0007 extends Activity {

    /* renamed from: class, reason: not valid java name */
    long[] f13class;

    /* renamed from: ő */
    int f11;

    /* renamed from: ő */
    long[] f12;

    public ActivityC0007() {
        while (true) {
            try {
                this.f13class = new long[]{40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821};
                this.f12 = new long[12];
                this.f11 = 0;
                return;
            } catch (Error | Exception e) {
            }
        }
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C0006R.layout.activity_main);
        final EditText editText = (EditText) findViewById(C0006R.id.editText);
        final TextView textView = (TextView) findViewById(C0006R.id.textView);
        ((Button) findViewById(C0006R.id.button)).setOnClickListener(new View.OnClickListener() { // from class: com.google.ctf.sandbox.ő.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                ActivityC0007.this.f11 = 0;
                try {
                    Object[] objArr = {65, 112, 112, 97, 114, 101, 110, 116, 108, 121, 32, 116, 104, 105, 115, 32, 105, 115, 32, 110, 111, 116, 32, 116, 104, 101, 32, 102, 108, 97, 103, 46, 32, 87, 104, 97, 116, 39, 115, 32, 103, 111, 105, 110, 103, 32, 111, 110, 63};
                    StringBuilder sb = new StringBuilder();
                    for (Object obj : objArr) {
                        sb.append(((Character) obj).charValue());
                    }
                    if (editText.getText().toString().equals(sb.toString())) {
                        textView.setText("��");
                    } else {
                        textView.setText("❌");
                    }
                } catch (Error | Exception e) {
                    String obj2 = editText.getText().toString();
                    if (obj2.length() != 48) {
                        textView.setText("❌");
                        return;
                    }
                    for (int i = 0; i < obj2.length() / 4; i++) {
                        ActivityC0007.this.f12[i] = obj2.charAt((i * 4) + 3) << 24;
                        long[] jArr = ActivityC0007.this.f12;
                        jArr[i] = jArr[i] | (obj2.charAt((i * 4) + 2) << 16);
                        long[] jArr2 = ActivityC0007.this.f12;
                        jArr2[i] = jArr2[i] | (obj2.charAt((i * 4) + 1) << '\b');
                        long[] jArr3 = ActivityC0007.this.f12;
                        jArr3[i] = jArr3[i] | obj2.charAt(i * 4);
                    }
                    ActivityC0007 activityC0007 = ActivityC0007.this;
                    if (((C0006R.m0(ActivityC0007.this.f12[ActivityC0007.this.f11], 4294967296L)[0] % 4294967296L) + 4294967296L) % 4294967296L != ActivityC0007.this.f13class[ActivityC0007.this.f11]) {
                        textView.setText("❌");
                        return;
                    }
                    ActivityC0007.this.f11++;
                    if (ActivityC0007.this.f11 < ActivityC0007.this.f12.length) {
                        throw new RuntimeException();
                    }
                    textView.setText("��");
                }
            }
        });
    }
}
```

We can see the encoding, that iterates over the **input of the user** (4 char) at a time and create the **array** of **12 values**.

We can make an **bruteforce** script in python using **numba** and **numpy** for a **high speed**.
Why?
The problem is that a normal script is taking too long or is getting “**stuck**” because:
- The **search space is huge**: `(128-32)^4 = 96^4 = 84,934,656` combinations per `4-character` segment.
In total -> `1,019,215,872` combinations!!!

So, here's a python script:
```python
import numpy as np
from numba import njit
from concurrent.futures import ProcessPoolExecutor
import sys

# No warns
@njit(fastmath=True)
def extended_gcd(a, b):
    if a == 0:
        return (0, 1)
    x, y = extended_gcd(b % a, a)
    return (y - (b // a) * x, x)

@njit
def find_segment_numba(target):
    for a0 in range(32, 127):
        for a1 in range(32, 127):
            for a2 in range(32, 127):
                for a3 in range(32, 127):
                    s = (a3 << 24) | (a2 << 16) | (a1 << 8) | a0
                    x, _ = extended_gcd(s, 4294967296)
                    if ((x % 4294967296 + 4294967296) % 4294967296) == target:
                        return (a0, a1, a2, a3)
    return (-1, -1, -1, -1)

def process_segment(target):
    result = find_segment_numba(target)
    if result[0] != -1:
        a0, a1, a2, a3 = result
        return bytes([a0, a1, a2, a3]).decode('latin-1')
    return "????"

if __name__ == "__main__":
    flag_values = [
        40999019, 2789358025, 656272715, 18374979,
        3237618335, 1762529471, 685548119, 382114257,
        1436905469, 2126016673, 3318315423, 797150821
    ]

    print("Starting optimized brute force search...")
    
    # Process segments
    with ProcessPoolExecutor() as executor:
        results = list(executor.map(process_segment, flag_values))
    
    flag = "".join(results)
    print("\nFinal flag:", flag)
```

Output:
```bash
Starting optimized brute force search...

Final flag: CTF{y0u_c4n_k3ep_y0u?_m4gic_1_h4Ue_laser_b3ams!}
```

![[googleCTF2020sandbox2.png]]

**`CTF{y0u_c4n_k3ep_y0u?_m4gic_1_h4Ue_laser_b3ams!}`**

I hope you found it useful (: