**Description**: A paid android app for THC began to be developed, unfortunately its development stalled. In the end, it was never possible to buy this app, but be the first to unlock the app's premium features by finding a valid key.

**Download**: https://lautarovculic.com/my_files/THC.apk

![[thc2018_1.png]]

Install the **APK** file with **ADB**
```bash
adb install -r THC.apk
```

We can see that we have the typical serial activation number.
The format is: `XXXX-XXXX-XXXX-XXXX`

So, let's inspect the **source code** with **jadx**.
There are **two activities** in `com.thc.bestpig.serial` package name.
**`MainActivity`** -> We have the input serial view ("home screen")
**`PremiumActivity`** -> May be the flag?

In `MainActivity` we see the `checkPassword` function:
```java
protected boolean checkPassword(String serial) {
    if (validateSerial(serial)) {
        new AlertDialog.Builder(this).setTitle("Well done ;)").setMessage("You can now validate this challenge.\n\nThe flag is the serial").setCancelable(false).setNeutralButton("Ok", new DialogInterface.OnClickListener() { // from class: com.thc.bestpig.serial.MainActivity.1
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                Intent intent = new Intent(MainActivity.this.getApplicationContext(), (Class<?>) PremiumActivity.class);
                MainActivity.this.startActivity(intent);
            }
        }).show();
        return true;
    }
    new AlertDialog.Builder(this).setTitle("Premium activation failed").setMessage("Please don't try random serial, buy a legit premium license to support developers.").setCancelable(false).setNeutralButton("Ok", new DialogInterface.OnClickListener() { // from class: com.thc.bestpig.serial.MainActivity.2
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialog, int which) {
        }
    }).show();
    return false;
}
```

We can see two messages: `Well done ;)` and `Premium activation failed`.
Also, the description.

But notice the difference between both, in the first `if` condition (which we need this), we have the `onClick()` method:
```java
public void onClick(DialogInterface dialog, int which) {
                Intent intent = new Intent(MainActivity.this.getApplicationContext(), (Class<?>) PremiumActivity.class);
                MainActivity.this.startActivity(intent);
            }
        }).show();
        return true;
```

Notice that this send an `Intent` to open `PremiumActivity`.
But before, in the first line, we have the `if` condition `validation`.
```java
if (validateSerial(serial)) {
[...]
[...]
[...]
```

Let's inspect the `validateSerial` function:
```java
protected boolean validateSerial(String serial) {
    return serial.length() == 19 
        && serial.charAt(4) == '-' 
        && serial.charAt(9) == '-' 
        && serial.charAt(14) == '-' 
        && serial.charAt(5) == serial.charAt(6) + 1 
        && serial.charAt(5) == serial.charAt(18) 
        && serial.charAt(1) == (serial.charAt(18) % 4) * 22 
        && ((serial.charAt(3) * serial.charAt(15)) / serial.charAt(17)) + (-1) == serial.charAt(10) 
        && serial.charAt(10) == serial.charAt(1) 
        && serial.charAt(13) == serial.charAt(10) + 5 
        && serial.charAt(10) == serial.charAt(5) + 65527 
        && (serial.charAt(0) % serial.charAt(7)) * serial.charAt(11) == 1440 
        && (serial.charAt(2) - serial.charAt(8)) + serial.charAt(12) == serial.charAt(10) + 65527 
        && (serial.charAt(3) + serial.charAt(12)) / 2 == serial.charAt(16) 
        && (serial.charAt(0) - serial.charAt(2)) + serial.charAt(3) == serial.charAt(12) + 15 
        && serial.charAt(3) == serial.charAt(13) 
        && serial.charAt(16) == serial.charAt(0) 
        && serial.charAt(7) + 1 == serial.charAt(2) 
        && serial.charAt(15) + 1 == serial.charAt(11) 
        && serial.charAt(11) + 3 == serial.charAt(17) 
        && serial.charAt(7) + 20 == serial.charAt(6);
}
```

Pay attention, this is an **String**! So, the length as we can see in the code is `19`.
So, in `XXXX-XXXX-XXXX-XXXX` the `-` are string.
Notice that piece of `serial.charAt()`
```java
&& serial.charAt(4) == '-' 
&& serial.charAt(9) == '-' 
&& serial.charAt(14) == '-' 
```
And their position.

Let's approach this by setting up the relationships and solving for each character.
We'll use ASCII values for characters

```python
"""
Brute-force serial (XXXX-XXXX-XXXX-XXXX).
Checks ASCII-based mathematical constraints between character positions.
Finds valid serials by testing combinations within printable ASCII range.
"""

def validate_serial(serial):
    if len(serial) != 19: return False
    if serial[4] != '-' or serial[9] != '-' or serial[14] != '-': return False
    
    s = [ord(c) for c in serial]
    conditions = [
        s[5] == s[6] + 1,
        s[5] == s[18],
        s[1] == (s[18] % 4) * 22,
        ((s[3] * s[15]) // s[17]) - 1 == s[10],
        s[10] == s[1],
        s[13] == s[10] + 5,
        s[10] == (s[5] + 65527) % 256,
        (s[0] % s[7]) * s[11] == 1440,
        (s[2] - s[8]) + s[12] == (s[10] + 65527) % 256,
        (s[3] + s[12]) // 2 == s[16],
        (s[0] - s[2]) + s[3] == s[12] + 15,
        s[3] == s[13],
        s[16] == s[0],
        s[7] + 1 == s[2],
        s[15] + 1 == s[11],
        s[11] + 3 == s[17],
        s[7] + 20 == s[6]
    ]
    return all(conditions)

def solve_serial():
    for s5 in range(33, 127):
        s6 = s5 - 1
        s18 = s5
        s10 = (s5 + 65527) % 256
        if (s18 % 4) * 22 != s10: continue
        
        s1 = s10
        s13 = s10 + 5
        s3 = s13
        s7 = s6 - 20
        if s7 <= 0: continue
            
        s2 = s7 + 1
        
        divisors = [i for i in range(1, 121) if 1440 % i == 0 and 1440 // i < 256]
        for s11 in divisors:
            if s11 <= 32 or s11 >= 127: continue
                
            s15 = s11 - 1
            s17 = s11 + 3
            if ((s3 * s15) // s17) - 1 != s10: continue
                
            target = 1440 // s11
            for s0 in range(33, 127):
                if s0 % s7 == target:
                    s16 = s0
                    s12 = 2 * s16 - s3
                    if (s0 - s2) + s3 != s12 + 15: continue
                        
                    s8 = s2 - ((s10 + 65527) % 256 - s12)
                    if s8 < 33 or s8 > 126: continue
                        
                    serial = [
                        s0, s1, s2, s3, ord('-'), s5, s6, s7, s8, ord('-'), s10, 
                        s11, s12, s13, ord('-'), s15, s16, s17, s18
                    ]
                    serial_str = ''.join(chr(c) for c in serial)
                    if validate_serial(serial_str):
                        return serial_str
    
    return "No solution found"

print("Serial:", solve_serial())
```

![[thc2018_2.png]]

![[thc2018_3.png]]

So, as the message say:
Flag: **`HB7G-KJ6G-BPIG-OHSK`**

I hope you found it useful (: