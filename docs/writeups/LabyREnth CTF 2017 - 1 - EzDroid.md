**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/EzDroid.apk

![[laby2017_ezdroid1.png]]

Install the **apk** with **adb**
```bash
adb install -r EzDroid.apk
```
The app doesn't launch, even if we start the activity with **adb**
```bash
adb shell am start -n com.labyrenth.manykeys.manykeys/.EZMain
```

So, let's decompile it with **apktool**
```bash
apktool d EzDroid.apk
```
And let's inspect the **source code** with **jadx**

And yes, here's the problem. In de **MainActivity**, we can see that in the **onCreate** method, we have an **if** condition that calls to another class with the `buh` method
```java
public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_ezmain);  
        final onoes classOne = new onoes();  
        if (classOne.checkers(this).booleanValue()) {  
            Toast.makeText(this, "You chose poor execution tactics...", 0).show();  
            classOne.buh();  
        }
[...]
[...]
[...]
```
And the `buh()` method is
```java
public void buh() {  
        Process.killProcess(Process.myPid());  
}
```

And the **checkers** that **onCreate** method are calling in `if (classOne.checkers(this).booleanValue())` are:
```java
public Boolean checkers(Context paramContext) {  
        boolean cheeky = false;  
        try {  
            TelephonyManager localTelephonyManager = (TelephonyManager) paramContext.getSystemService("phone");  
            if (Build.PRODUCT.contains("sdk")) {  
                cheeky = true;  
            } else if (Build.MODEL.contains("sdk")) {  
                cheeky = true;  
            } else if (localTelephonyManager.getSimOperatorName().equals("Android")) {  
                cheeky = true;  
            } else if (localTelephonyManager.getNetworkOperatorName().equals("Android")) {  
                cheeky = true;  
            } else {  
                cheeky = false;  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return cheeky;  
    }
```

So, the value is `True` if our `PRODUCT` or `MODEL` contains **sdk** and also the **Android** compassion. So, while that is `True`, then the `buh()` method will be called.
**`Else`**, this will don't call the `buh()` function.

So, we need modify the **smali** file that contains this **hardcoded** strings. We can replace `sdk` and `Android` words by *any random string value*.
```bash
cat onoes.smali | grep -E "sdk|Android" -n
```
Output:
```bash
61:    const-string v4, "sdk"
86:    const-string v4, "sdk"
109:    const-string v4, "Android"
132:    const-string v4, "Android"
```
Here's are the line numbers of the **code** that we need change. I modify the `onoes.smali` with
```bash
61:    const-string v4, "QQQQQQQQ"
86:    const-string v4, "QQQQQQQQQ"
109:    const-string v4, "QQQQQQQQQ"
132:    const-string v4, "QQQQQQQQQQQQQ"
```

So now, we need **rebuild** the app.
We can use **apktool**
```bash
apktool b EzDroid
```

And then, generate a **key**
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

Now, **sign** the apk
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore EzDroid/dist/EzDroid.apk alias
```

And, uninstall the original app from the emulator, and install the **new apk**
```bash
adb install -r EzDroid/dist/EzDroid.apk
```

And now we can see the activity:
![[laby2017_ezdroid1.png]]

Notice that the code now will execute this line
`String sVal = classOne.retIt();`
This line call to `retIt()` method from `onoes` class.
```java
public String retIt() {  
        String outpoot = new Object() { // from class: com.labyrenth.manykeys.manykeys.onoes.1  
            int t;  
  
            public String toString() {  
                this.t = -1041749503;  
                this.t = -1865645093;  
                this.t = -1972361451;  
                this.t = -1779558645;  
                this.t = 339200404;  
                this.t = 1725700009;  
                this.t = -1760823842;  
                this.t = -1727695801;  
                this.t = -685164605;  
                this.t = 1706546180;  
                this.t = 757601807;  
                this.t = -979820414;  
                this.t = -660212506;  
                byte[] buf = {(byte) (this.t >>> 5), (byte) (this.t >>> 9), (byte) (this.t >>> 7), (byte) (this.t >>> 18), (byte) (this.t >>> 2), (byte) (this.t >>> 4), (byte) (this.t >>> 13), (byte) (this.t >>> 22), (byte) (this.t >>> 20), (byte) (this.t >>> 15), (byte) (this.t >>> 21), (byte) (this.t >>> 14), (byte) (this.t >>> 12)};  
                return new String(buf);  
            }  
        }.toString();  
        return outpoot;  
    }
```

Then, this is the value that the **System.out.println** is showed, we can use **logcat** with **adb**
```bash
adb logcat -c && adb logcat | grep Part
```
Output:
```bash
I/System.out( 8828): Part1: PAN{ez_droid_
```
We can see that the **flag is building**.
So, let's keep doing the challenge for complete the flag.

Now we need work with this part of the **EzMain** activity code
```java
String sVal = classOne.retIt();  
        System.out.println("Part1: " + sVal);  
        final String[] hints = {"two plus one", "one plus one", "five plus two", "three plus zero", "nine minus two", "two plus two", "three plus three", "eleven minus ten", "negative two plus nine", "one plus one", "five plus two", "three plus one"};  
        final ArrayList<Integer> inputs = new ArrayList<>();  
        final EditText getInput = (EditText) findViewById(R.id.enter_key_one);  
        getInput.setHint(hints[0]);  
        Button clickButton = (Button) findViewById(R.id.next_button);  
        clickButton.setOnClickListener(new View.OnClickListener() { // from class: com.labyrenth.manykeys.manykeys.EZMain.1  
            int i = 1;  
  
            @Override // android.view.View.OnClickListener  
            public void onClick(View view) {  
                String newInput = getInput.getText().toString().trim();  
                int input = Integer.parseInt(newInput);  
                inputs.add(Integer.valueOf(input));  
                if (this.i != 12) {  
                    getInput.setHint(hints[this.i]);  
                    getInput.setText("");  
                    this.i++;  
                    return;  
                }  
                if (!Build.PRODUCT.contains("sdk")) {  
                    EZMain.this.checks(inputs);  
                } else {  
                    Toast.makeText(EZMain.this, "You're in an emulator...", 0).show();  
                    SystemClock.sleep(200L);  
                    Process.killProcess(Process.myPid());  
                }  
                SystemClock.sleep(1000L);  
                System.out.println("You should have the key...soon");  
                SystemClock.sleep(1000L);  
                classOne.buh();  
            }  
        });
```
The correct order of **value** that we must insert is `3 2 7 3 7 4 6 1 7 2 7 4`
But, when we send the last number, the app crash again.
So, there are some bypass that we must to do.
```java
if (!Build.PRODUCT.contains("sdk")) {  
    EZMain.this.checks(inputs);
```
Here, as previously we do, change `sdk` for any random characters.
Remember, now the **patch** must be in the **new** builded apk, that is in `EzDroid/dist/EzDroid.apk`
For work better, move the **apk** to our actual directory.
`mv EzDroid/dist/EzDroid.apk EzDroid2.apk` and rename with `2`
Because we must decompile it with **apktool** again for access to the `smali files`.
```bash
cat EZMain\$1.smali | grep "sdk"

141:    const-string v3, "sdk"
```
So in `/EzDroid2/smali/com/labyrenth/manykeys/manykeys` we need modify the file `EZMain\$1.smali`.

Rebuild the apk and sign as previously we has been do.
```bash
apktool b EzDroid2
```
And
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore EzDroid2/dist/EzDroid2.apk alias
```
Uninstall the **app** and reinstall the new apk
```bash
adb install -r EzDroid2/dist/EzDroid2.apk
```
Run the new apk installed and then, complete the inputs with this values
`3 2 7 3 7 4 6 1 7 2 7 4` while you are running the **logcat** command

```bash
adb logcat -c && adb logcat | grep Part
```
Notice that the **app** is crashing. But the logs show the **second part** of the challenge
```bash
I/System.out( 8828): Part1: PAN{ez_droid_
I/System.out( 8828): Part 2: 2start_
```
At this point, the flag is **`PAN{ez_droid_2star`**

Let keep doing the CTF.
The app crashes when this line is executed
`Boolean outAns = classTwo.lastCheck("72657031616365746831732121");`
The Code of below is the rest
```java
Boolean outAns = classTwo.lastCheck("72657031616365746831732121");  
        if (outAns.booleanValue()) {  
            System.out.println("You did it, put the key together...");  
        } else {  
            System.out.println("FAILURE");  
        }
```

So, at this point, we need look the `lastCheck` method in `onoes` class.
And too, the `getHexString` that will give us the **flag**.
```java
public Boolean lastCheck(String strValue) {  
        boolean result;  
        if ((Long.parseLong(strValue) * (-37)) + 42 == 17206538691L) {  
            result = true;  
            getHexString(strValue);  
            System.out.println("\nDid you get it?  You should know...");  
        } else {  
            result = false;  
            System.out.println("\nfalse");  
        }  
        return Boolean.valueOf(result);  
    }  
  
    public void getHexString(String strval) {  
        String outie = "" + strval.charAt(14) + strval.charAt(3) + strval.charAt(14) + strval.charAt(11) + strval.charAt(5) + strval.charAt(4) + strval.charAt(14) + strval.charAt(13) + strval.charAt(19) + strval.charAt(6) + strval.charAt(14) + strval.charAt(13) + strval.charAt(14) + strval.charAt(1) + strval.charAt(14) + strval.charAt(14) + strval.charAt(14) + strval.charAt(1) + strval.charAt(14) + strval.charAt(11) + strval.charAt(5) + strval.charAt(13);  
        String outtput = hexToASCII(outie);  
        System.out.println("Final Part: " + outtput + "}");  
    }
```

If you notice the log when the app crashes, it show some like
```bash
Process: com.labyrenth.manykeys.manykeys, PID: 11729
java.lang.NumberFormatException: Invalid long: "72657031616365746831732121"
```
That means that there an error formatting.
Because, the string (72657031616365746831732121) is `20` chars and `long values` take 19 digits (20 but 1 less by index 0). Probably, the number is **negative** for take all `20` chars.
The string `72657031616365746831732121` from `hex` is
```bash
echo '72657031616365746831732121' | xxd -r  -p
```
Output: **rep1aceth1s!!**

That seems like we need found a **correct value for `strValue`** of the `lastCheck` class.
The **condition** is here
```java
if ((Long.parseLong(strValue) * (-37)) + 42 == 17206538691L) {  
            result = true;  
            getHexString(strValue);  
            System.out.println("\nDid you get it?  You should know...");
```
That, is **if True**, then the **getHexString take the value** and give us the flag.

So now, we need get the **real value** for this.
The problem involves integer overflow in Java's Long data type. We're trying to solve:

`37x = 17206538649 (mod 2^64)`
Long variables in Java use 64 bits, so when they overflow, they wrap around. To find x:
1. Calculate the minimum overflow:
`MAX_LONG + (0 - MIN_LONG + 1) + Overflow`
In Java, a `long` can hold values from negative `9,223,372,036,854,775,808` to positive `9,223,372,036,854,775,807`
2. Keep adding 2^64 until you get a number divisible by 37.
3. Divide the result by 37 to get x.

`9223372036854775807 + (0 - -9223372036854775808 + 1) + 17206538649`
`9223372036854775807 + 9223372036854775809 + 17206538649`
`2^64 + 17206538649`
Then, the overflow is **18446744090916090265**
Let's **bruteforce** for get the **value**.
Here's a **python** script
```python
from decimal import Decimal, getcontext

# Set precision high enough to handle these calculations
getcontext().prec = 100

max_long = Decimal("9223372036854775807")
min_long = Decimal("-9223372036854775808")
mod_base = Decimal(2) ** 64
target = Decimal("17206538691")

# Calculate overflow
overflow = (target - min_long + 1 - 42 + max_long)
print(f"Overflow: {overflow}")

def get_p3(d):
    pos = [14,3,14,11,5,4,14,13,19,6,14,13,14,1,14,14,14,1,14,11,5,13]
    part3 = ''.join(d[p] for p in pos)
    return ''.join(chr(int(part3[i:i+2], 16)) for i in range(0, len(part3), 2))

for i in range(100):
    mul = mod_base * i
    val = mul + overflow
    
    remainder = val % -37
    quotient = val // -37
    q_len = len(str(quotient))
    
    if remainder == 0:
        quotient = val // -37
        p3 = get_p3(str(quotient).zfill(64))
        p3_len = len(str(quotient))
        print(f"\t{i}: {p3} ({quotient} : {p3_len})")

print("Calculation complete.")
```

Output:  `11:  (-5982727808154625893 : 20)`
Now, we need **modify** again the **smali** file.
```bash
cat EZMain.smali | grep "72657031616365746831732121" -n

142:   const-string v7, "72657031616365746831732121"
```
Change `72657031616365746831732121` by `-5982727808154625893` and then, rebuild again the apk. You must know the process.

Installing the last **apk**, reproduce all the **steps** with **logcat** running.
```bash
  lautaro   ~/Desktop/CTF/MOBILE/labyREnth_2017/ezdroid  catn sequence.txt
3 2 7 3 7 4 6 1 7 2 7 4

  lautaro   ~/Desktop/CTF/MOBILE/labyREnth_2017/ezdroid  adb install -r EzDroid_Final.apk
Performing Push Install
EzDroid_Final.apk: 1 file pushed, 0 skipped. 622.8 MB/s (1323698 bytes in 0.002s)
	pkg: /data/local/tmp/EzDroid_Final.apk
Success

  lautaro   ~/Desktop/CTF/MOBILE/labyREnth_2017/ezdroid  adb logcat -c && adb logcat | grep Part

I/System.out(14286): Part1: PAN{ez_droid_
I/System.out(14286): Part 2: 2start_
I/System.out(14286): Final Part: hard2defeat}
```

Final flag
**`PAN{ez_droid_2start_hard2defeat}`**

I hope you found it useful (: