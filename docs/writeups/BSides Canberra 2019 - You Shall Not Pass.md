**Download**: https://lautarovculic.com/my_files/PasswordCheckerAPKs.zip

![[bsides_2019-passwordChecker1.png]]

Install the *correct APK*, depends of your *cpu device*. You can check with
```bash
getprop ro.product.cpu.abi
```

In my case, is `arm64-v8a`.
Then, install with **ADB**
```bash
adb install -r PasswordChecker-arm64-v8a.apk
```

We can see a *simply password checker*.
That *return **true** or **false***.
Let's inspect the **source code** with **jadx** (GUI version).
And, **decompile it** with **apktool**
```bash
apktool d PasswordChecker-arm64-v8a.apk
```

We have the *package name* `io.cybears.rev.passwordchecker` and just one activity (**MainActivity**). And just the code that exists for our interest is the Main
```java
public class MainActivity extends AppCompatActivity {  
    public native String checkPassword(String str);  
  
    public native String checkPassword2(String str);  
  
    public native String checkPassword3(String str);  
  
    public native String stringFromJNI();  
  
    static {  
        System.loadLibrary("native-lib");  
    }  
    
    public void onCreate(Bundle bundle) {  
        super.onCreate(bundle);  
        setContentView(R.layout.activity_main);  
    }  
  
    public void checkPassword(View view) {  
        String charSequence = ((TextView) findViewById(R.id.editText)).getText().toString();  
        Toast.makeText(getApplicationContext(), "RESULT:" + checkPassword3(charSequence), 0).show();  
    }  
}
```

Well, the only thing that we can check is the *libraries*. It can be found inside of the **lib** directory that **apktool** drop.
Let's open it with **ghidra**.

We just need need inspect the **`checkPassword3`** function from the *libnative*.
![[bsides_2019-passwordChecker2.png]]

The *flag* start with the *string* `cybears`. This may be **useful** for work with the script.

This script uses the **Z3 symbolic solver** to model the constraints given in the disassembly code. **Each byte of the flag is defined as a symbolic variable** (`Int`), and the disassembly conditions are **translated into mathematical constraints**. Then, *Z3 finds values that satisfy all the constraints*, thus constructing the flag.

I noticed this because the problem involves **many algebraic constraints**, which is ideal for *Z3*, since it solves **logical satisfiability problems with symbolic expressions**. In addition, the script technique avoids iterative or bruteforce approaches, focusing on solving all constraints simultaneously.

Here's the python script:
```python
from z3 import *

def solve_flag():
    # create Z3 solver
    solver = Solver()

    # flag representing
    flag = [Int(f'b_{i}') for i in range(23)]

    # Restrict ASCII bytes for printers
    for byte in flag:
        solver.add(byte >= 32, byte <= 126)

    # conditions
    known_prefix = "cybears"
    for i, char in enumerate(known_prefix):
        solver.add(flag[i] == ord(char))

    # dissasemble conditions, add
    solver.add(flag[9] - flag[3] - flag[14] - flag[16] == -114)
    solver.add(flag[6] + flag[17] * flag[0] == 10213)
    solver.add(flag[14] * flag[21] - flag[10] * flag[10] == -6190)
    solver.add(flag[20] + flag[12] - flag[16] == 112)
    solver.add(flag[6] + flag[21] + flag[11] == 261)
    solver.add(flag[3] * flag[1] + flag[10] * flag[13] == 20201)
    solver.add(flag[8] + flag[16] * flag[7] == 6601)
    solver.add(flag[22] * flag[19] - flag[9] == 6290)
    solver.add(flag[12] * flag[14] * flag[21] == 184275)
    solver.add(flag[4] - flag[17] * flag[15] - flag[19] == -4952)
    solver.add(flag[1] * flag[1] - flag[18] == 14592)
    solver.add(flag[10] - (flag[8] + flag[22]) == -112)
    solver.add(flag[1] - flag[4] == 24)
    solver.add(flag[21] * flag[19] * flag[5] == 366282)
    solver.add(flag[8] + flag[15] + flag[11] * flag[14] == 3866)
    solver.add(flag[16] + flag[1] == 174)
    solver.add(flag[11] - flag[6] * flag[4] * flag[15] == -546512)
    solver.add(flag[16] * flag[21] * flag[4] - flag[5] == 323769)
    solver.add(flag[11] * flag[3] - flag[17] * flag[4] == -1511)
    solver.add(flag[9] + flag[16] - flag[5] * flag[14] == -4992)
    solver.add(flag[21] - flag[6] * flag[22] == -14312)
    solver.add(flag[0] - flag[19] * flag[17] * flag[6] == -598131)

    # restrictions resolve
    if solver.check() == sat:
        model = solver.model()
        flag_result = ''.join(chr(model[flag[i]].as_long()) for i in range(23))
        return flag_result
    else:
        return "Error"

if __name__ == "__main__":
    print("Flag:", solve_flag())
```

If we insert the flag to *password checker* app, the *result* is **true**.
Flag: **`cybears{RU_SAT-15f13d?}`**

I hope you found it useful (: