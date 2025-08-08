![[pedometer1.png]]**Difficult:** Hard
**Category**: Mobile
**OS**: Android

**Description**: I've been using this pedometer app for weeks, and I am convinced it's using me as a power supply for some hidden machine. I bet it holds the key or a map to some sort of treasure. If only I could figure out what it's doing…

-----------------
Download the **.zip** file and extract this with the password **hackthebox**.
Decompile the **apk** with **apktool**
```bash
apktool d pedometer.apk
```

Let’s install the apk in our **Android 12**.
![[pedometer2.png]]

Let’s walk around the **source code** with **JD-GUI**.
We have just **one activity**, which is `MainActivity`.

### `MainActivity.java`
```java
public final class MainActivity extends l {
    public SensorManager u;

    public c v;

    public final void n() {
        Object object = getSystemService("sensor");
        e.w(object, "null cannot be cast to non-null type android.hardware.SensorManager");
        object = object;
        this.u = (SensorManager) object;
        object = object.getDefaultSensor(1);
        SensorManager sensorManager = this.u;
        if (sensorManager != null) {
            sensorManager.registerListener((SensorEventListener) new a(this), (Sensor) object, 3);
            return;
        } 
        object = new d("lateinit property sensorManager has not been initialized");
        e.c1((RuntimeException) object);
        throw object;
    }

    public final void onCreate(Bundle paramBundle) {
        super.onCreate(paramBundle);
        setContentView(2131427356);
        c c1 = new c(0);
        a a = new a(this);
        StringBuilder stringBuilder = new StringBuilder("activity_rq#");
        stringBuilder.append(((k) this).h.getAndIncrement());
        String str = stringBuilder.toString();
        d d = ((k) this).i.c(str, (r) this, c1, a);
        if (e.a((Context) this, "android.permission.ACTIVITY_RECOGNITION") == 0) {
            n();
        } else {
            d.w1();
        } 
        this.v = new c(this);
    }
}
```

This code initialize the step sensor (*accelerometer*) and trigger the execution of the *malicious logic* (or *challenge*) when it detects movement:
- `c c1 = new c(0);`
Creates **an instance of a permissions handler** (`ActivityResultContract`, from package `b.c`) that *asks for permissions*.

- `a a = new a(this);`
**Creates an anonymous class** (`u1.a`) that extends `SensorEventListener`, in *charge of handling sensor events*.

- `d = ((k)this).i.c(...)`
**Registers a handler for the response of the `ACTIVITY_RECOGNITION` permission**. If already granted, calls `n()`. If not, it *triggers the permission request*.

- `this.v = new c(this);`
**Here is the key**. It creates an **instance of `u1.c`**, which **opens `assets/a`** (the *bytecode of the virtual machine*). That is, it **prepares the VM to be used later**.

### What is a Virtual Machine (VM)?
A virtual machine (VM) in this **context is a custom interpreter that executes specific intermediate instructions**, often **encrypted or obfuscated**, without relying on the *original language or architecture of the device*.
In this challenge, the VM is **fed by instructions stored in `assets/a`**, and **executes** each in response to *accelerometer events*.
This **file contains instructions for the VM encrypted** by **dynamic XOR with a `d` value** that is *modified during execution*.

Where find the `assets/a` file?
When we *decompile the `apk` file* with **apktool**, inside of the new directory, we can found the `assets` directory.
```bash
file a
```
Output:
```bash
a: data
```

```bash
strings a
```
Output:
```bash
|V|"Lu8u
E111A
Ar	rVB^
nIMI(yd
Tuuu*E^
s%C5
lR\^a^9nYrY	izSz
JCYC
```

```bash
hexdump a
```
Output:
```bash
0000000 0101 0001 0101 0101 0101 0101 0101 0101
0000010 20f0 0040 20f1 0040 20f2 0040 20f0 0040
0000020 2a01 2bf3 2b60 1b1d 567c 227c 754c 7538
0000030 4508 3131 4131 7101 7189 41fa 0972 5672
0000040 5e42 5e96 6ede 4d49 2849 6479 64dd 54a9
0000050 7575 2a75 5e45 5eca 6eb9 c872 8372 4a42
0000060 4ad5 7aa7 1173 2573 3543 3591 05fc 0d6c
0000070 526c 5e5c 5e61 6e39 7259 0959 7a69 7a53
0000080 4a11 5943 0d43 5573 55bd 65f5 ffbc 0000
000008f
```

Let's continue with the challenge.
#### Example:
Instead of **directly coding instructions** like “*add two numbers*” in Java, the application **delegates that logic to a VM**. This **machine reads opcodes** such as **`PUSH`**, **`ADD`**, **`XOR`**, **`BUILD_FLAG`**, etc., from a *binary file and executes the operations dynamically*.

This **technique is common in malware**, *emulators*, and also in `CTFs` to hide *the real logic of a program*.

### What are Opcodes?
The opcodes (**operation codes**) are **numeric codes that tell the VM which operation to execute**. They are the *basis of the bytecode interpreted by the virtual machine*.
In this challenge, the *opcodes are defined* by **enum** `u1.b`.

```java
package u1;

public enum b {
    public final int a;

    b(String paramString) {
        this.a = this$enum$index;
    }
}
```

### What are the challenge opcodes?
These were extracted using Frida with the following script:
```javascript
Java.perform(function () {
    var Op = Java.use("u1.b");
    var vals = Op.values();
    for (var i = 0; i < vals.length; i++) {
        console.log(i + " => 0x" + vals[i].a.value.toString(16));
    }
});
```
Output:
```bash
0 => 0x0
1 => 0x1
2 => 0x2
3 => 0x10
4 => 0x11
5 => 0x12
6 => 0x13
7 => 0x14
8 => 0x20
9 => 0x21
10 => 0x22
11 => 0x30
12 => 0x31
13 => 0x40
14 => 0x41
15 => 0xf0
16 => 0xf1
17 => 0xf2
18 => 0xf3
19 => 0xf4
20 => 0xff
```

### Class `u1.c`
This class is the **core of the VM**, where the **state**, **input** and **execution stack** are **stored**.
The code:
```java
public final class c {
    public final MainActivity a;

    public final InputStream b;

    public final Stack c;

    public int d;

    public c(MainActivity paramMainActivity) {
        this.a = paramMainActivity;
        InputStream inputStream = paramMainActivity.getAssets().open("a");
        e.x(inputStream, "main.assets.open(\"a\")");
        this.b = inputStream;
        this.c = new Stack();
    }

    public final int a() {
        Stack<Integer> stack = this.c;
        Integer integer = stack.peek();
        stack.pop();
        e.x(integer, "value");
        return integer.intValue();
    }
}
```

This class:
- **Loads** the `assets/a` file as `InputStream`.
- **Initializes** a **LIFO** stack.
- Declares a `d` register that **is used for dynamic XOR operations**.

This class **does not execute instructions**, but is **used by the interpreter** (`u1.a`) to perform **stack operations**, *read bytes from the file and maintain context between instructions*.

### Class `u1.a` implements `SensorEventListener` - Virtual Machine Interpreter
This class is t*he interpreter that executes instructions when motion is detected* in the **accelerometer**:
```java
package u1;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import com.rloura.pedometer.MainActivity;

public final class a implements SensorEventListener {
    public final MainActivity a;

    public int b;

    public long c;

    public a(MainActivity paramMainActivity) {
        this.a = paramMainActivity;
    }

    public final void onAccuracyChanged(Sensor paramSensor, int paramInt) {}

    public final void onSensorChanged(SensorEvent paramSensorEvent) {
        // Byte code:
        //   0: invokestatic getInstance : ()Ljava/util/Calendar;
        //   3: invokevirtual getTimeInMillis : ()J
        //   6: aload_0
        //   7: getfield c : J
        //   10: lsub
        //   11: ldc2_w 300
        //   14: lcmp
        //   15: ifle -> 850
        //   18: aload_0
        //   19: invokestatic getInstance : ()Ljava/util/Calendar;
        //   22: invokevirtual getTimeInMillis : ()J
        //   25: putfield c : J
        //   28: aload_1
        //   29: invokestatic v : (Ljava/lang/Object;)V
        //   32: aload_1
        //   33: getfield values : [F
        //   36: astore_1
        //   37: iconst_0
        //   38: istore_2
        //   39: aload_1
        //   40: iconst_0
        //   41: faload
        //   42: f2i
[...]
[...]
[...]
[...]
```
Notice that we have 850 commented lines.
This is bytecode that **JD-GUI** try understand.
Obviously, this code is a **little hard to understand**. So we can use the **AI power** for "*convert/translate*" the code.

You can *choose literally any kind of language programming*.
I use *Claude AI* and convert the *bytecode* to *java code* for a better understanding.
```java
public final void onSensorChanged(SensorEvent paramSensorEvent) {
    // We check if at least 300ms have elapsed since the last update.
    if (Calendar.getInstance().getTimeInMillis() - this.c > 300) {
        // We update the time of the last update
        this.c = Calendar.getInstance().getTimeInMillis();
        
        // We obtain the sensor values
        float[] values = paramSensorEvent.values;
        
        // If the absolute value of the first value is greater than 6 (probably the acceleration)
        if (Math.abs((int)values[0]) > 6) {
            // We increase the step counter
            int stepCount = this.b;
            stepCount++;
            this.b = stepCount;
            
            // We updated the user interface with the new step count.
            MainActivity mainActivity = this.a;
            ((TextView) mainActivity.findViewById(2131231140)).setText(String.valueOf(stepCount));
            
            // Check if the step reader is initialized
            u1.c stepReader = mainActivity.v;
            if (stepReader != null) {
                InputStream inputStream = stepReader.b;
                
                // We check if there is data available to read
                if (inputStream.available() <= 0) {
                    return;
                }
                
                // We read a byte from the input stream
                int opCode = inputStream.read();
                int accumulator = stepReader.d;
                
                // We look for the operation corresponding to the operation code
                u1.b[] operations = u1.b.values();
                boolean found = false;
                
                for (u1.b operation : operations) {
                    if (operation.a == (opCode ^ accumulator)) {
                        found = true;
                        
                        // We process the operation according to its ordinal
                        int ordinal = operation.ordinal();
                        Stack<Integer> stack = stepReader.c;
                        MainActivity activity = stepReader.a;
                        
                        switch (ordinal) {
                            case 0: // SKIP
                                int bytesToSkip = inputStream.available();
                                inputStream.skip(bytesToSkip);
                                break;
                                
                            case 1: // READ_XOR
                                int value = inputStream.read();
                                int result = accumulator ^ value;
                                stack.push(result);
                                break;
                                
                            case 2: // POP
                                stack.pop();
                                break;
                                
                            case 3: // ADD
                                int a = stepReader.a();
                                int b = stepReader.a();
                                stack.push(b + a);
                                break;
                                
                            case 4: // SUB
                                int minuend = stepReader.a();
                                int subtrahend = stepReader.a();
                                stack.push(subtrahend - minuend);
                                break;
                                
                            case 5: // MUL
                                int factor1 = stepReader.a();
                                int factor2 = stepReader.a();
                                stack.push(factor2 * factor1);
                                break;
                                
                            case 6: // DIV
                                int divisor = stepReader.a();
                                int dividend = stepReader.a();
                                stack.push(dividend / divisor);
                                break;
                                
                            case 7: // MOD
                                int modulo = stepReader.a();
                                int modDividend = stepReader.a();
                                stack.push(modDividend % modulo);
                                break;
                                
                            case 8: // EQUALS
                                boolean isEqual = stepReader.a() == stepReader.a();
                                stack.push(isEqual ? 1 : 0);
                                break;
                                
                            case 9: // LESS_THAN
                                boolean isLessThan = stepReader.a() > stepReader.a();
                                stack.push(isLessThan ? 1 : 0);
                                break;
                                
                            case 10: // GREATER_THAN
                                boolean isGreaterThan = stepReader.a() < stepReader.a();
                                stack.push(isGreaterThan ? 1 : 0);
                                break;
                                
                            case 11: // IS_ZERO
                                boolean isZero = stepReader.a() == 0;
                                stack.push(isZero ? 1 : 0);
                                break;
                                
                            case 12: // XOR
                                int xorA = stepReader.a();
                                int xorB = stepReader.a();
                                int xorResult = xorA ^ xorB;
                                stack.push(xorResult);
                                stepReader.d = xorResult;
                                break;
                                
                            case 13: // PUSH_IF_ONE
                                if (stepReader.a() == 1) {
                                    int valueToPush = stepReader.a();
                                    stepReader.d = valueToPush;
                                }
                                break;
                                
                            case 14: // SET_ACC
                                int newAccumulator = stepReader.a();
                                stepReader.d = newAccumulator;
                                break;
                                
                            case 15: // CHECK_CHARGING
                                BatteryManager batteryManager = (BatteryManager) activity.getSystemService("batterymanager");
                                Intent batteryStatus = activity.registerReceiver(null, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
                                
                                int status = -1;
                                if (batteryStatus != null) {
                                    status = batteryStatus.getIntExtra("status", -1);
                                }
                                
                                boolean isCharging = status == 2 || status == 5;
                                boolean result1 = batteryManager.isCharging() || isCharging;
                                stack.push(result1 ? 1 : 0);
                                break;
                                
                            case 16: // CHECK_AIRPLANE_MODE
                                boolean airplaneMode = Settings.System.getInt(activity.getContentResolver(), "airplane_mode_on", 0) != 0;
                                stack.push(airplaneMode ? 1 : 0);
                                break;
                                
                            case 17: // CHECK_CONNECTIVITY
                                ConnectivityManager connectivityManager = (ConnectivityManager) activity.getSystemService("connectivity");
                                boolean isConnected = false;
                                
                                if (connectivityManager.getActiveNetworkInfo() != null) {
                                    NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
                                    isConnected = networkInfo.isConnected();
                                }
                                
                                stack.push(isConnected ? 1 : 0);
                                break;
                                
                            case 18: // LOAD_ACC
                                int loadedValue = stepReader.a();
                                stepReader.d = loadedValue;
                                break;
                                
                            case 19: // RESET_ACC
                                stepReader.d = 0;
                                break;
                                
                            case 20: // READ_STRING
                                char[] charArray = new char[0];
                                
                                for (int i = 1; i < 22; i++) {
                                    char c = (char) stepReader.a();
                                    charArray = Arrays.copyOf(charArray, charArray.length + 1);
                                    charArray[charArray.length - 1] = c;
                                }
                                
                                String resultString = new String(charArray);
                                ((TextView) activity.findViewById(2131230911)).setText(resultString);
                                break;
                                
                            default:
                                // Operation not recognized
                                break;
                        }
                        break;
                    }
                }
                
                // If a valid operation was not found
                if (!found) {
                    throw new NoSuchElementException("Array contains no element matching the predicate.");
                }
            } else {
                // The stepReader is not initialized
                RuntimeException e = new RuntimeException("lateinit property stepReader has not been initialized");
                throw e;
            }
        }
    }
}
```

### Understanding its behavior
- **Runs whenever** there is a **significant change** in motion.
- **Reads a byte** from **file `a`**.
- **Decrypts it with dynamic XOR** using the value `d`.
- **Finds what operation** it *represents* (using **enum `u1.b`**).
- **Executes the operation** by *manipulating the stack or updating* `d`.
- If the **opcode is `0xFF`** (`BUILD_FLAG`), it **rebuilds the flag from the stack and displays it**.

This is a typical implementation of a minimalist stack-based VM, which *executes bytecode instruction by instruction*.

### Getting the flag
The **Python script replicates the VM**, *decrypting and executing the instructions* in the file to **obtain the flag**.

```python
data_bytes_le = [
    0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0xf0, 0x20, 0x40, 0x00, 0xf1, 0x20, 0x40, 0x00, 0xf2, 0x20, 0x40, 0x00, 0xf0, 0x20, 0x40, 0x00,
    0x01, 0x2a, 0xf3, 0x2b, 0x60, 0x2b, 0x1d, 0x1b, 0x7c, 0x56, 0x7c, 0x22, 0x4c, 0x75, 0x38, 0x75,
    0x08, 0x45, 0x31, 0x31, 0x31, 0x41, 0x01, 0x71, 0x89, 0x71, 0xfa, 0x41, 0x72, 0x09, 0x72, 0x56,
    0x42, 0x5e, 0x96, 0x5e, 0xde, 0x6e, 0x49, 0x4d, 0x49, 0x28, 0x79, 0x64, 0xdd, 0x64, 0xa9, 0x54,
    0x75, 0x75, 0x75, 0x2a, 0x45, 0x5e, 0xca, 0x5e, 0xb9, 0x6e, 0x72, 0xc8, 0x72, 0x83, 0x42, 0x4a,
    0xd5, 0x4a, 0xa7, 0x7a, 0x73, 0x11, 0x73, 0x25, 0x43, 0x35, 0x91, 0x35, 0xfc, 0x05, 0x6c, 0x0d,
    0x6c, 0x52, 0x5c, 0x5e, 0x61, 0x5e, 0x39, 0x6e, 0x59, 0x72, 0x59, 0x09, 0x69, 0x7a, 0x53, 0x7a,
    0x11, 0x4a, 0x43, 0x59, 0x43, 0x0d, 0x73, 0x55, 0xbd, 0x55, 0xf5, 0x65, 0xbc, 0xff, 0x00, 0x00
]

opcode_by_value = {
    0x0: 0, 0x1: 1, 0x2: 2, 0x10: 3, 0x11: 4, 0x12: 5, 0x13: 6, 0x14: 7,
    0x20: 8, 0x21: 9, 0x22: 10, 0x30: 11, 0x31: 12, 0x40: 13, 0x41: 14,
    0xF0: 15, 0xF1: 16, 0xF2: 17, 0xF3: 18, 0xF4: 19, 0xFF: 20
}

class VM:
    def __init__(self, code):
        self.code = code
        self.ptr = 0
        self.stack = []
        self.d = 0
        self.flag = None

    def read_byte(self):
        if self.ptr >= len(self.code):
            return None
        b = self.code[self.ptr]
        self.ptr += 1
        return b

    def pop(self):
        return self.stack.pop() if self.stack else 0

    def push(self, val):
        self.stack.append(val & 0xFFFFFFFF)

    def run(self):
        while self.ptr < len(self.code):
            byte = self.read_byte()
            if byte is None:
                break
            opcode_val = byte ^ self.d
            ordinal = opcode_by_value.get(opcode_val)
            if ordinal is None:
                continue

            if ordinal == 0:  # SKIP_REST
                continue
            elif ordinal == 1:  # PUSH
                param = self.read_byte()
                if param is None:
                    break
                val = param ^ self.d
                self.push(val)
            elif ordinal == 2:  # POP
                self.pop()
            elif ordinal == 3:  # ADD
                a, b = self.pop(), self.pop()
                self.push(b + a)
            elif ordinal == 4:  # SUB
                a, b = self.pop(), self.pop()
                self.push(b - a)
            elif ordinal == 5:  # MUL
                a, b = self.pop(), self.pop()
                self.push(b * a)
            elif ordinal == 6:  # DIV
                a, b = self.pop(), self.pop()
                self.push(b // a if a else 0)
            elif ordinal == 7:  # MOD
                a, b = self.pop(), self.pop()
                self.push(b % a if a else 0)
            elif ordinal == 8:  # EQ
                a, b = self.pop(), self.pop()
                self.push(1 if b == a else 0)
            elif ordinal == 9:  # LT
                a, b = self.pop(), self.pop()
                self.push(1 if a < b else 0)
            elif ordinal == 10:  # GT
                a, b = self.pop(), self.pop()
                self.push(1 if a > b else 0)
            elif ordinal == 11:  # NOT
                self.push(1 if self.pop() == 0 else 0)
            elif ordinal == 12:  # XOR and update d
                a, b = self.pop(), self.pop()
                res = b ^ a
                self.d = res & 0xFF
                self.push(res)
            elif ordinal == 13:  # COND_SKIP
                cond = self.pop()
                if cond == 1:
                    n = self.pop()
                    self.ptr += n
            elif ordinal == 14:  # SKIP_N
                n = self.pop()
                self.ptr += n
            elif ordinal == 15:  # BATTERY_STATUS
                self.push(0)
            elif ordinal == 16:  # AIRPLANE_MODE
                self.push(0)
            elif ordinal == 17:  # CONNECTIVITY
                self.push(1)
            elif ordinal == 18:  # POP_TO_D
                self.d = self.pop() & 0xFF
            elif ordinal == 19:  # RESET_D
                self.d = 0
            elif ordinal == 20:  # BUILD_FLAG
                chars = [chr(self.pop() & 0xFF) for _ in range(22)]
                self.flag = ''.join(chars[::-1])
                break
        return self.flag

# execute VM
vm = VM(data_bytes_le)
flag = vm.run()
correct_flag = flag[::-1]  # -1 to the flag
print("Flag:", correct_flag)
```

#### Explanation of the script
##### Initialization
- `ptr`: **pointer** to the **current byte**.
- `stack`: **execution stack** where *intermediate values are stored*.
- `d`: **dynamic XOR value** used to *decrypt instructions*.
- `flag`: final result extracted.

##### Main execution
- **Reads each byte and performs XOR with `d`** to determine the *opcode*.
- **The opcode defines the specific operation** to be *executed*.
- **Updates the value of d according to specific instructions** to *decrypt subsequent bytes*.

##### Key instructions explained
- **PUSH (`0x01`)**: Places an *encrypted value* on the stack.
- **XOR and update `d` (`0x31`)**: Performs *XOR with values on the stack* and updates `d`.
- **COND_SKIP (`0x40`)**: *Skips instructions* if a specific condition *is met*.
- **BUILD_FLAG (`0xFF`)**: *Generates the flag by reading 22 characters* from the stack.

Flag: **`HTB{X_m4rKs_teH_sp0t}`**

I hope you found it useful (: