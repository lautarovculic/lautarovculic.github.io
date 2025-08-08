### AHE16 : Android Hacking Events 2016
For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

For download the **APK**
https://team-sik.org/wp-content/uploads/2016/06/strangecalculator.apk_.zip

![[strangeCalculator1.png]]

We install the **apk** with
```bash
adb install -r strangecalculator.apk
```

And then, decompile this with **apktool**
```bash
apktool d strangecalculator.apk
```
Let's inspect the **source code** with **jadx** (GUI Version)
We have 2 activities, **MainActivity** and **Parser** activity.

Let's talk about **MainActivity** (Code can be shorted for the writeup)
```java
package de.ecspride.demoversion;  

public class MainActivity extends ActionBarActivity {  
    private View view;  
  
    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_main);  
        this.view = findViewById(R.id.txtExpression);  
    }  
  
    public boolean onCreateOptionsMenu(Menu menu) {  
        getMenuInflater().inflate(R.menu.main, menu);  
        return true;  
    }  
  
    public boolean onOptionsItemSelected(MenuItem item) {  
        int id = item.getItemId();  
        if (id == R.id.action_settings) {  
            return true;  
        }  
        return super.onOptionsItemSelected(item);  
    }  
  
    public void createBackground(View v) {  
        String s = ((EditText) this.view).getText().toString();  
        try {  
            TextView result = (TextView) findViewById(R.id.lblResult);  
            result.setText("");  
            result.setText(String.valueOf(Parser.eval(s)));  
        } catch (Exception e) {  
            Toast.makeText(this, e.getMessage(), 1).show();  
        }  
    }  
}
```

Here's nothing important code to analyze. So, let's explain the **Parser** activity.
```java
package de.ecspride.demoversion;  
  
import android.util.Log;  
  
/* loaded from: classes.dex */  
public class Parser {  
    /* JADX WARN: Type inference failed for: r0v0, types: [de.ecspride.demoversion.Parser$1InternalParser] */  
    public static double eval(final String str) {  
        return new Object() { // from class: de.ecspride.demoversion.Parser.1InternalParser  
            int c;  
            int pos = -1;  
  
            void eatChar() {  
                int i = this.pos + 1;  
                this.pos = i;  
                this.c = i < str.length() ? str.charAt(this.pos) : (char) 65535;  
            }  
  
            void eatSpace() {  
                while (Character.isWhitespace(this.c)) {  
                    eatChar();  
                }  
            }  
  
            double parse() {  
                eatChar();  
                double v = parseExpression();  
                if (this.c != -1) {  
                    throw new RuntimeException("Unexpected: " + ((char) this.c));  
                }  
                return v;  
            }  
  
            double parseExpression() {  
                double v = parseTerm();  
                while (true) {  
                    eatSpace();  
                    if (this.c == 43) {  
                        eatChar();  
                        v += parseTerm();  
                    } else {  
                        if (this.c != 45) {  
                            break;  
                        }  
                        eatChar();  
                        v -= parseTerm();  
                    }  
                }  
                if (v > 100.0d) {  
                    throw new RuntimeException("The number is too large. Please buy the full version!");  
                }  
                if (v > 100.0d) {  
                    int[] flarry = {1400, 1393, 1404, 1288, 1295, 1346, 1395, 1368, 1359, 1368, 1382, 1293, 1367, 1368, 1365, 1344, 1354, 1288, 1354, 1382, 1288, 1354, 1382, 1355, 1293, 1357, 1361, 1290, 1355, 1382, 1290, 1368, 1354, 1344, 1382, 1288, 1354, 1367, 1357, 1382, 1288, 1357, 1348};  
                    for (int i : flarry) {  
                        Log.d("SUPER OUTPUT", Integer.toString(i ^ 1337));  
                    }  
                }  
                return v;  
            }  
  
            double parseTerm() {  
                double v = parseFactor();  
                while (true) {  
                    eatSpace();  
                    if (this.c == 47) {  
                        eatChar();  
                        v /= parseFactor();  
                    } else if (this.c == 42 || this.c == 40) {  
                        if (this.c == 42) {  
                            eatChar();  
                        }  
                        v *= parseFactor();  
                    } else {  
                        return v;  
                    }  
                }  
            }  
  
            double parseFactor() {  
                double v;  
                boolean negate = false;  
                eatSpace();  
                if (this.c == 40) {  
                    eatChar();  
                    v = parseExpression();  
                    if (this.c == 41) {  
                        eatChar();  
                    }  
                } else {  
                    if (this.c == 43 || this.c == 45) {  
                        negate = this.c == 45;  
                        eatChar();  
                        eatSpace();  
                    }  
                    StringBuilder sb = new StringBuilder();  
                    while (true) {  
                        if ((this.c < 48 || this.c > 57) && this.c != 46) {  
                            break;  
                        }  
                        sb.append((char) this.c);  
                        eatChar();  
                    }  
                    if (sb.length() == 0) {  
                        throw new RuntimeException("Unexpected: " + ((char) this.c));  
                    }  
                    v = Double.parseDouble(sb.toString());  
                }  
                eatSpace();  
                if (this.c == 94) {  
                    eatChar();  
                    v = Math.pow(v, parseFactor());  
                }  
                return negate ? -v : v;  
            }  
        }.parse();  
    }
```

This is the **entire** code of the activity.
Take a time for analyze the code, if you pay attention, you can notice that this two **if conditions** is repeated:
```java
if (v > 100.0d) {  
                    throw new RuntimeException("The number is too large. Please buy the full version!");  
                }  
if (v > 100.0d) {  
                    int[] flarry = {1400, 1393, 1404, 1288, 1295, 1346, 1395, 1368, 1359, 1368, 1382, 1293, 1367, 1368, 1365, 1344, 1354, 1288, 1354, 1382, 1288, 1354, 1382, 1355, 1293, 1357, 1361, 1290, 1355, 1382, 1290, 1368, 1354, 1344, 1382, 1288, 1354, 1367, 1357, 1382, 1288, 1357, 1348};  
                    for (int i : flarry) {  
                        Log.d("SUPER OUTPUT", Integer.toString(i ^ 1337));  
                    }  
                }
```

These two conditions are **equals**, both compare if **v** (final value) is **>** than 100.
But, **only the first one is executed**.
So, the second condition is **skipped** (because the first is already executed)

Then, we need modify **and rebuild** the **app** from the **smali** code.
But before, let me explain the **second condition**
```java
if (v > 100.0d) {  
                    int[] flarry = {1400, 1393, 1404, 1288, 1295, 1346, 1395, 1368, 1359, 1368, 1382, 1293, 1367, 1368, 1365, 1344, 1354, 1288, 1354, 1382, 1288, 1354, 1382, 1355, 1293, 1357, 1361, 1290, 1355, 1382, 1290, 1368, 1354, 1344, 1382, 1288, 1354, 1367, 1357, 1382, 1288, 1357, 1348};  
                    for (int i : flarry) {  
                        Log.d("SUPER OUTPUT", Integer.toString(i ^ 1337));  
                    }  
                }
```

If the result **(v)** is **>** than **100**, then there is an array called **flarry** and there are an **XOR** operation with **1337** in every **element**, then, is passed via **log** with
`Log.d("SUPER OUTPUT", Integer.toString(i ^ 1337))`

Let's modify the **smali** file of the **activity**.
```bash
/smali/de/ecspride/demoversion
.
└── Parser$1InternalParser.smali
```

We can do **many** ways of modify the **smali** for bypass the first **if**.
But in this case, this is a **writeup** and not a **smali lesson**. In a future Ill write a blog about **smali** in deep.
For now, we can go to **Parser$1InternalParser.smali**
And searching for **100**
we can see
```smali
229     .line 42
230     :cond_1
231     const-wide/high16 v4, 0x4059000000000000L    # 100.0
232
233     cmpl-double v4, v2, v4
234
235     if-lez v4, :cond_2
236
237     .line 43
238     new-instance v4, Ljava/lang/RuntimeException;
239
240     const-string v5, "The number is too large. Please buy the full version!"
241
242     invoke-direct {v4, v5}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V
243
244     throw v4
245
246     .line 47
247     :cond_2
248     const-wide/high16 v4, 0x4059000000000000L    # 100.0
```

We need change the `244     throw v4` line to an **nop** for bypass the **throw** exception.
The final **piece of code** must look like:
```smali
229     .line 42
230     :cond_1
231     const-wide/high16 v4, 0x4059000000000000L    # 100.0
232
233     cmpl-double v4, v2, v4
234
235     if-lez v4, :cond_2
236
237     .line 43
238     new-instance v4, Ljava/lang/RuntimeException;
239
240     const-string v5, "The number is too large. Please buy the full version!"
241
242     invoke-direct {v4, v5}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V
243
244     nop # < ----- HERE 
245
246     .line 47
247     :cond_2
248     const-wide/high16 v4, 0x4059000000000000L    # 100.0
```

Now it's time to **rebuild** the apk with **apktool**
```bash
apktool b strangecalculator
```

And now let's generate a **key**
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

And now, we need **sign** the apk with **apksigner**
```bash
apksigner sign --ks name.keystore --ks-key-alias alias --out apk.apk strangecalculator/dist/strangecalculator.apk
```

If we close our **previous** apk project in **jadx**, and open the **apk.apk** file, we can notice that the code has changed:
```java
if (v > 100.0d) {  
                    new RuntimeException("The number is too large. Please buy the full version!");  
}
```

The **throw** is gone!

**Uninstall** the **original app** and install the **apk.apk** file
```bash
adb install -r apk.apk
```

Now go to the **app** and set in a terminal the following command for **inspect the logs**
```bash
adb logcat
```

Make an **operation** that the result is **> 100** and you can see the following output:
```bash
D/SUPER OUTPUT( 8114): 65
D/SUPER OUTPUT( 8114): 72
D/SUPER OUTPUT( 8114): 69
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 54
D/SUPER OUTPUT( 8114): 123
D/SUPER OUTPUT( 8114): 74
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 118
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 52
D/SUPER OUTPUT( 8114): 110
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 108
D/SUPER OUTPUT( 8114): 121
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 114
D/SUPER OUTPUT( 8114): 52
D/SUPER OUTPUT( 8114): 116
D/SUPER OUTPUT( 8114): 104
D/SUPER OUTPUT( 8114): 51
D/SUPER OUTPUT( 8114): 114
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 51
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 121
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 110
D/SUPER OUTPUT( 8114): 116
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 116
D/SUPER OUTPUT( 8114): 125
```

There is an ASCII chars.
Use the following code in python
```python
def ascii_to_string(ascii_codes):
    # Get only numbers from the list
    numbers = [int(line.split(':')[1].strip()) for line in ascii_codes.split('\n') if line.strip()]
    
    # Convert and union
    return ''.join(chr(num) for num in numbers)

# ASCII
ascii_input = """
D/SUPER OUTPUT( 8114): 65
D/SUPER OUTPUT( 8114): 72
D/SUPER OUTPUT( 8114): 69
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 54
D/SUPER OUTPUT( 8114): 123
D/SUPER OUTPUT( 8114): 74
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 118
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 52
D/SUPER OUTPUT( 8114): 110
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 108
D/SUPER OUTPUT( 8114): 121
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 114
D/SUPER OUTPUT( 8114): 52
D/SUPER OUTPUT( 8114): 116
D/SUPER OUTPUT( 8114): 104
D/SUPER OUTPUT( 8114): 51
D/SUPER OUTPUT( 8114): 114
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 51
D/SUPER OUTPUT( 8114): 97
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 121
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 115
D/SUPER OUTPUT( 8114): 110
D/SUPER OUTPUT( 8114): 116
D/SUPER OUTPUT( 8114): 95
D/SUPER OUTPUT( 8114): 49
D/SUPER OUTPUT( 8114): 116
D/SUPER OUTPUT( 8114): 125
"""

# Convert and show result
result = ascii_to_string(ascii_input)
print(result)
```

Run the script and get the **output**:
```bash
AHE16{Java_4nalys1s_1s_r4th3r_3asy_1snt_1t}
```

We can avoide the **patch**, **rebuild**, **analysis** process from the start of the **CTF**.
Because, we can use the **java** logic and pass to **python** script like:
```python
def process_value(v):
    if v > 100.0:
        flarry = [1400, 1393, 1404, 1288, 1295, 1346, 1395, 1368, 1359, 1368, 1382, 1293, 1367, 1368, 1365, 1344, 1354, 1288, 1354, 1382, 1288, 1354, 1382, 1355, 1293, 1357, 1361, 1290, 1355, 1382, 1290, 1368, 1354, 1344, 1382, 1288, 1354, 1367, 1357, 1382, 1288, 1357, 1348]

        result = ""
        for i in flarry:
            decoded_char = chr(i ^ 1337)
            print("SUPER OUTPUT", i ^ 1337)
            result += decoded_char

        print("Decoded message:", result)

    return v

v = 150.0
process_value(v)
```

But this isn't the **intention** in the **learning path**.

I hope you found it useful (: