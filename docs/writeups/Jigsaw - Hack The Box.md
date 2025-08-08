![[jigsaw1.png]]
**Difficult:** Easy
**Category**: Mobile
**OS**: Android

**Description**: A secret lies hidden, protected by layers of logic and scattered clues. Your task is to uncover these fragments, piece them together, and solve the mystery. It’s a challenge of patience, creativity, and determination. Can you reveal the secret?

----

Install the **APK** file using **ADB**
```bash
adb install -r Jigsaw.apk
```
We can see a *login activity*.
Let's *decompile the `apk`* using **apktool**
```bash
apktool d Jigsaw.apk
```

Also, we will use **JADX** for see the *source code*.
```bash
jadx-gui Jigsaw.apk
```
We just have an activity, and some interesting classes.

When the app is decompiled, *apktool* drop us an `/assets/flutter_assets` directory.
Inside, we have **`kernel_blob.bin`** file.
Looking for `strings`, we can get the **Dart source code** of the *application*.

**`services.dart`**:
```dart
import 'dart:ffi';
class AESService {

  static const platform = MethodChannel('parttwo');
  Future<Map<String, List<int>>> getparttwo() async {
    try {

      final Map<dynamic, dynamic> result = await platform.invokeMethod('parttwo');
      return {
        "key": List<int>.from(result['key']),
        "iv": List<int>.from(result['iv']),
      };
    } on PlatformException catch (e) {
      print("Failed to get parttwo: '${e.message}'.");
      return {};
    }
typedef GetAESKeyNative = Pointer<Uint8> Function();
typedef GetAESIVNative = Pointer<Uint8> Function();
class AESNativeLib {
  final DynamicLibrary _dylib;
  // Private constructor
  AESNativeLib._(this._dylib);
  // Singleton instance
  static AESNativeLib? _instance;
  // Load the shared library and return the instance
  static AESNativeLib get instance {
    _instance ??= AESNativeLib._(DynamicLibrary.open('libmenascyber.so'));
    return _instance!;
  List<int> getAESKey() {
    final getAESKey = _dylib
        .lookupFunction<GetAESKeyNative, GetAESKeyNative>('partthree_1');
    final keyPointer = getAESKey();
    return keyPointer.asTypedList(32);
  List<int> getAESIV() {
    final getAESIV = _dylib
        .lookupFunction<GetAESIVNative, GetAESIVNative>('partthree_2');
    final ivPointer = getAESIV();
    return ivPointer.asTypedList(16);
class AESCombinedService {
  final AESNativeLib _nativeLib = AESNativeLib.instance;
  final AESService _aesService = AESService();
   // Hardcoded key and IV
  final List<int> _hardcodedKey = List<int>.generate(32, (i) => (i + 1) % 256);
  final List<int> _hardcodedIV = List<int>.generate(16, (i) => (i + 10) % 256);
  // Deterministic shuffling method
  List<int> _deterministicShuffle(List<int> input, int shift) {
    return List<int>.generate(input.length, (i) {
      return input[(i + shift) % input.length];
    });
  Future<Map<String, List<int>>> partone() async {
    // Shuffle the key and IV deterministically
    final shuffledKey = _deterministicShuffle(_hardcodedKey, 5);
    final shuffledIV = _deterministicShuffle(_hardcodedIV, 3);
    return {
      "key": shuffledKey,
      "iv": shuffledIV,
    };
  Future<Map<String, List<int>>> getflag() async {
    final partoneData = await partone();
    final parttwoData = await _aesService.getparttwo();
    final partthreeKey = _nativeLib.getAESKey();
    final partthreeIV = _nativeLib.getAESIV();
    // Combine and slice the key and IV from each part
    final combinedKey = [
      ...partoneData['key']!.sublist(0, 8),
      ...parttwoData['key']!.sublist(0, 8),
      ...partthreeKey.sublist(0, 16)
    ];
    final combinedIV = [
      ...partoneData['iv']!.sublist(0, 4),
      ...parttwoData['iv']!.sublist(0, 4),
      ...partthreeIV.sublist(0, 8)
    ];
    return {
      "key": combinedKey,
      "iv": combinedIV,
    };
```

**`main.dart`**
```dart
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/material.dart';
import 'package:jigsaw/services.dart';
import  'package:ffi/ffi.dart';
import 'package:jigsaw/flag.dart';
void main() {
  runApp(MyApp());
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Login App',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: LoginPage(),
    );
class LoginPage extends StatefulWidget {
  @override
  _LoginPageState createState() => _LoginPageState();
class _LoginPageState extends State<LoginPage> {
  final TextEditingController _usernameController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final AESCombinedService _aesCombinedService = AESCombinedService();
 Future<void> fetchAndDecryptFlag() async {
    try {
      final finallyClass = Finally();
      final decryptedFlag = await finallyClass.decryptFlag();

    } catch (e) {

    }
  void _login() {
    // Check if the username and password are correct
    if (_usernameController.text == 'nimda' && _passwordController.text == 'guessme') {

      Navigator.push(
        context,
        MaterialPageRoute(builder: (context) => HomePage(username: _usernameController.text)),
      );
    } else {
      showDialog(
        context: context,
        builder: (context) {
          return AlertDialog(
            title: Text('Login Failed'),
            content: Text('Crack me and find the flag'),
            actions: [
              TextButton(
                onPressed: () {
                  Navigator.of(context).pop();
                },
                child: Text('OK'),
              ),
            ],
          );
        },
      );
    }
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [Colors.blue, Colors.blueAccent],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              Text(
                'Welcome Back!',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 32,
                  fontWeight: FontWeight.bold,
                ),
              ),
              SizedBox(height: 20),
              TextField(
                controller: _usernameController,
                style: TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Username',
                  labelStyle: TextStyle(color: Colors.white),
                  filled: true,
                  fillColor: Colors.white.withOpacity(0.2),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(15),
                    borderSide: BorderSide.none,
                  ),
                  prefixIcon: Icon(Icons.person, color: Colors.white),
                ),
              ),
              SizedBox(height: 20),
              TextField(
                controller: _passwordController,
                style: TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Password',
                  labelStyle: TextStyle(color: Colors.white),
                  filled: true,
                  fillColor: Colors.white.withOpacity(0.2),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(15),
                    borderSide: BorderSide.none,
                  ),
                  prefixIcon: Icon(Icons.lock, color: Colors.white),
                ),
                obscureText: true,
              ),
              SizedBox(height: 20),
              ElevatedButton(
                onPressed: _login,
                style: ElevatedButton.styleFrom(
                  padding: EdgeInsets.symmetric(horizontal: 60, vertical: 10),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(15),
                  ),
                  backgroundColor: Colors.white,
                ),
                child: Text(
                  'Login',
                  style: TextStyle(
                    fontSize: 18,
                    color: Colors.blueAccent,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
class HomePage extends StatelessWidget {
  final String username;
  HomePage({required this.username});
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Home Page'),
      ),
     body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Image.asset(
              'assets/images/laughing.png', // Ensure you have this image in your assets folder
              width: 150,
              height: 150,
            ),
            SizedBox(height: 20),
            Text(
              'Sorry, no flag here.',
              style: TextStyle(
                fontSize: 24,
                color: Colors.redAccent,
              ),
            ),
          ],
        ),
      ),
    );
```

**`flag.dart`**
```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:jigsaw/services.dart'; // Import the file containing AESCombinedService
class Finally {
  final String _encryptedFlagBase64 = 'aZ/KF0GsnN81j5XStQyKz3vXtktTVN5zFqy5lwTmub6fx5w70c+p08O0OWcn/9nh';
  Future<String> decryptFlag() async {

    final aesService = AESCombinedService();
    final flagData = await aesService.getflag();

    final encryptedFlagBytes = _base64ToBytes(_encryptedFlagBase64);

    final key = Uint8List.fromList(flagData['key']!);
    final iv = Uint8List.fromList(flagData['iv']!);
    final encryptKey = encrypt.Key(key);
    final encryptIV = encrypt.IV(iv);
    final encrypter = encrypt.Encrypter(encrypt.AES(encryptKey, mode: encrypt.AESMode.cbc));
    final decrypted = encrypter.decrypt(
      encrypt.Encrypted.fromBase64(_encryptedFlagBase64),
      iv: encryptIV,
    );



    //return decrypted;


     String message = "Developer forgot to uncomment";
     return  message;
 // Helper function to convert base64 string to bytes
  List<int> _base64ToBytes(String base64) {
    final bytes = base64Decode(base64);
    return bytes;
  String bytesToHex(Uint8List bytes) {
  final buffer = StringBuffer();
  for (var byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  return buffer.toString();
```

Also, we can found a **native library** in
```bash
ls lib/arm64-v8a
```
Output:
```bash
libmenascyber.so
```

The `libmenascyber.so` will be useful in further.
For now, let's focus in **dart code**.
Notice in `flag.dart` this line:
```dart
final String _encryptedFlagBase64 = 'aZ/KF0GsnN81j5XStQyKz3vXtktTVN5zFqy5lwTmub6fx5w70c+p08O0OWcn/9nh';
```
This is the base64 flag. It is protected with AES CBC. The key and IV are obtained with
```dart
final flagData = await aesService.getflag();
```

### Part One - Hardcoded Key/IV con Shuffle
In `services.dart` we have:
```dart
final List<int> _hardcodedKey = List<int>.generate(32, (i) => (i + 1) % 256);
final List<int> _hardcodedIV  = List<int>.generate(16, (i) => (i + 10) % 256);

_deterministicShuffle(input, shift) => input[(i + shift) % input.length];
```
This function performs a deterministic shift of the elements. For `partone()` we take:
```dart
shuffledKey = _deterministicShuffle(_hardcodedKey, 5).sublist(0, 8);
shuffledIV  = _deterministicShuffle(_hardcodedIV, 3).sublist(0, 4);
```

Let's use a *python script* that take the first part of the `key` and `iv`.
```python
def deterministic_shuffle(input_list, shift):
    return [input_list[(i + shift) % len(input_list)] for i in range(len(input_list))]

hardcoded_key = [(i + 1) % 256 for i in range(32)]
hardcoded_iv  = [(i + 10) % 256 for i in range(16)]

# Apply shuffle & cut
key1 = bytes(deterministic_shuffle(hardcoded_key, 5)[:8])
iv1  = bytes(deterministic_shuffle(hardcoded_iv, 3)[:4])

print("key1 =", key1.hex())
print("iv1  =", iv1.hex())
```

Output:
```bash
key1 = 060708090a0b0c0d
iv1  = 0d0e0f10
```

Fun fact, in `main.dart` we have fake creds which are:
- `nimda`:`guessme`
```dart
if (_usernameController.text == 'nimda' && _passwordController.text == 'guessme')
```
But a image will appear after login, just a little rabbit hole.

### Part Two - Flutter Channel & Kotlin Logic
Let's move into the **source code** with **JADX**.
We have the  `MainActivity.java`, `MainActivityKt.java` and `piecesOf.kt`.
The app implements a `MethodChannel` to respond to the “`parttwo`” method from Dart:

**`MainActivty.java`**
```java
public final class MainActivity extends FlutterActivity {
    private final String CHANNEL = "parttwo";

    @Override // io.flutter.embedding.android.FlutterActivity, io.flutter.embedding.android.FlutterActivityAndFragmentDelegate.Host, io.flutter.embedding.android.FlutterEngineConfigurator
    public void configureFlutterEngine(FlutterEngine flutterEngine) {
        Intrinsics.checkNotNullParameter(flutterEngine, "flutterEngine");
        super.configureFlutterEngine(flutterEngine);
        new MethodChannel(flutterEngine.getDartExecutor().getBinaryMessenger(), this.CHANNEL).setMethodCallHandler(new MethodChannel.MethodCallHandler() { // from class: com.example.menascyber.MainActivity$ExternalSyntheticLambda0
            @Override // io.flutter.plugin.common.MethodChannel.MethodCallHandler
            public final void onMethodCall(MethodCall methodCall, MethodChannel.Result result) {
                MainActivity.configureFlutterEngine$lambda$0(methodCall, result);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void configureFlutterEngine$lambda$0(MethodCall call, MethodChannel.Result result) {
        Map response;
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(result, "result");
        if (Intrinsics.areEqual(call.method, "parttwo")) {
            response = MainActivityKt.get_parttwo();
            result.success(response);
        } else {
            result.notImplemented();
        }
    }
}
```

**`MainActivityKt.java`**
```java
public final class MainActivityKt {
    /* JADX INFO: Access modifiers changed from: private */
    public static final Map<String, byte[]> get_parttwo() {
        byte[] keyFirst18 = ArraysKt.copyOfRange(piecesOf.INSTANCE.getParttwo_1(), 0, 18);
        byte[] ivFirst18 = ArraysKt.copyOfRange(piecesOf.INSTANCE.getParttwo_2(), 0, 7);
        return MapsKt.mapOf(TuplesKt.m88to("key", keyFirst18), TuplesKt.m88to("iv", ivFirst18));
    }
}
```

And the **most important** part:
**`piecesOf.java`**
```java
public final class piecesOf {
    public static final piecesOf INSTANCE;
    private static final byte[] oB1;
    private static final byte[] oB2;
    private static final byte[] parttwo_1;
    private static final byte[] parttwo_2;
    private static final byte[] xP1;
    private static final byte[] xP2;

    private piecesOf() {
    }

    static {
        piecesOf piecesof = new piecesOf();
        INSTANCE = piecesof;
        byte[] bArr = {90, 107, 124, -115, -98, -81, -80, -63, -46, -29, -12, 5, 22, 39, 56, 73};
        xP1 = bArr;
        byte[] bArr2 = {26, 43, 60, 77, 94, 111, 112, -127, -110, -93, -76, -59, -42, -25, -8, 9};
        xP2 = bArr2;
        byte[] bArr3 = {96, Base64.padSymbol, -21, 16, 21, -54, 113, -66, 43, 115, -82, -16, -123, 125, 119, -127, 31, 53, 44, 7, 59, 97, 8, -41, 45, -104, 16, -93, 9, 20, -33, -12};
        oB1 = bArr3;
        byte[] bArr4 = {-96, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        oB2 = bArr4;
        parttwo_1 = piecesof.m48tB(bArr3, bArr);
        parttwo_2 = piecesof.m48tB(bArr4, bArr2);
    }

    /* renamed from: rR */
    private final byte m47rR(byte v, int c) {
        return (byte) ((v >> c) | (v << (8 - c)));
    }

    /* renamed from: tB */
    private final byte[] m48tB(byte[] i, byte[] p) {
        int length = i.length;
        byte[] bArr = new byte[length];
        for (int i2 = 0; i2 < length; i2++) {
            bArr[i2] = INSTANCE.m47rR((byte) (i[i2] ^ p[i2 % p.length]), 3);
        }
        return bArr;
    }

    public final byte[] getParttwo_1() {
        return parttwo_1;
    }

    public final byte[] getParttwo_2() {
        return parttwo_2;
    }

    public final String bytesToHex(byte[] bytes) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        return ArraysKt.joinToString$default(bytes, (CharSequence) "", (CharSequence) null, (CharSequence) null, 0, (CharSequence) null, (Function1) new Function1<Byte, CharSequence>() { // from class: com.example.menascyber.piecesOf$bytesToHex$1
            public final CharSequence invoke(byte it) {
                StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
                String format = String.format("%02x", Arrays.copyOf(new Object[]{Byte.valueOf(it)}, 1));
                Intrinsics.checkNotNullExpressionValue(format, "format(format, *args)");
                return format;
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ CharSequence invoke(Byte b) {
                return invoke(b.byteValue());
            }
        }, 30, (Object) null);
    }
}
```

The `tB()` function performs XOR between two arrays and then applies **3-bit right rotation on each byte**:
```java
/* renamed from: rR */
private final byte m47rR(byte v, int c) {
    return (byte) ((v >> c) | (v << (8 - c)));
}

/* renamed from: tB */
private final byte[] m48tB(byte[] i, byte[] p) {
    int length = i.length;
    byte[] bArr = new byte[length];
    for (int i2 = 0; i2 < length; i2++) {
        bArr[i2] = INSTANCE.m47rR((byte) (i[i2] ^ p[i2 % p.length]), 3);
    }
    return bArr;
}
```
And the **arrays**
```java
xP1 = new byte[]{90, 107, 124, -115, -98, -81, -80, -63, -46, -29, -12, 5, 22, 39, 56, 73};
oB1 = new byte[]{96, 61, -21, 16, 21, -54, 113, -66, 43, 115, -82, -16, -123, 125, 119, -127, 31, 53, 44, 7, 59, 97, 8, -41, 45, -104, 16, -93, 9, 20, -33, -12};

xP2 = new byte[]{26, 43, 60, 77, 94, 111, 112, -127, -110, -93, -76, -59, -42, -25, -8, 9};
oB2 = new byte[]{-96, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
```

We can simplify this process using a *python script*:
```python
def rotate_right(val, n):
    return ((val >> n) | ((val << (8 - n)) & 0xFF)) & 0xFF

def tB(oB, xP):
    return bytes([rotate_right(oB[i] ^ xP[i % len(xP)], 3) for i in range(len(oB))])

# data
oB1 = bytes([
    96, 61, 235, 16, 21, 202, 113, 190,
    43, 115, 174, 240, 133, 125, 119, 129,
    31, 53, 44, 7, 59, 97, 8, 215,
    45, 152, 16, 163, 9, 20, 223, 244
])
xP1 = bytes([
    90, 107, 124, 141, 158, 175, 176, 193,
    210, 227, 244, 5, 22, 39, 56, 73
])

oB2 = bytes([
    160, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15
])
xP2 = bytes([
    26, 43, 60, 77, 94, 111, 112, 129,
    146, 163, 180, 197, 214, 231, 248, 9
])

# Apply XOR + ROTR (randFunc2)
parttwo_1 = tB(oB1, xP1)
parttwo_2 = tB(oB2, xP2)

# slicing
key2 = parttwo_1[:8]
iv2  = parttwo_2[:4]

print("key2 =", key2.hex())
print("iv2  =", iv2.hex())
```

Output:
```bash
key2 = 47caf2b371ac38ef
iv2  = 5745c7c9
```

### Part Three - Dump with Frida from libs
Open **ghidra** and *import* the `libmenascyber.so` library. Then, *analyze*.
We can see the functions that we need for complete the IV and key:
- `partthree_1()` => returns **32 bytes** (key)
- `partthree_2()` => returns **16 bytes** (IV)
These bytes are also derived with `randFunc2` based on *hardcoded data within the binary*.

Let's dump the value using **FRIDA**. For this, I develop this script:
```javascript
const lib = Module.findBaseAddress("libmenascyber.so");

function dump(name, size) {
  const fn = Module.findExportByName("libmenascyber.so", name);
  const ptr = new NativeFunction(fn, "pointer", [])();
  console.log(name, hexdump(ptr, { length: size, header: false }));
}

dump("partthree_1", 16);
dump("partthree_2", 8);
```

Run in interactive mode after `frida -U "Jigsaw"` command and the output is:
```hex
[KEY] Dumped:
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
79b02fab60  0b 4d cf d1 53 55 d6 d8 5b 5d df c1 43 45 c6 c8  .M..SU..[]..CE..
79b02fab70  49 4f cd d3 51 57 d4 da 03 23 43 63 83 a3 c3 e3  IO..QW...#Cc....

[KEY 32B]              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
79b02fab60  0b 4d cf d1 53 55 d6 d8 5b 5d df c1 43 45 c6 c8  .M..SU..[]..CE..
79b02fab70  49 4f cd d3 51 57 d4 da 03 23 43 63 83 a3 c3 e3  IO..QW...#Cc....

partthree_1 79b02fab60  0b 4d cf d1 53 55 d6 d8 5b 5d df c1 43 45 c6 c8  .M..SU..[]..CE..

[IV] Dumped:
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
79b02fab80  57 51 d3 dd 5f 59 da c4 47 41 c3 cd 4f 49 ca d4  WQ.._Y..GA..OI..

[IV 16B]              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
79b02fab80  57 51 d3 dd 5f 59 da c4 47 41 c3 cd 4f 49 ca d4  WQ.._Y..GA..OI..

partthree_2 79b02fab80  57 51 d3 dd 5f 59 da c4                          WQ.._Y..
```

So, the `key3` and `iv3` is `0b4dcfd15355d6d85b5ddfc14345c6c8` and `5751d3dd5f59dac4` respectively.

Final **`key`** and **`IV`**:
```python
key = key1 + key2 + key3  # 32 bytes
iv  = iv1  + iv2  + iv3   # 16 bytes
```
Also, the **cyphertext**:
- `aZ/KF0GsnN81j5XStQyKz3vXtktTVN5zFqy5lwTmub6fx5w70c+p08O0OWcn/9nh`

We can *put all together and decrypt using python*:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# keys
key = bytes([
    # partone (first 8 bytes)
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,

    # parttwo1 (using rot_r3 + signed handling)
    0x47, 0xca, 0xf2, 0xf3, 0xf1, 0xac, 0xf8, 0xef,

    # partthree1 (dumped from frida)
    0x0b, 0x4d, 0xcf, 0xd1, 0x53, 0x55, 0xd6, 0xd8,
    0x5b, 0x5d, 0xdf, 0xc1, 0x43, 0x45, 0xc6, 0xc8
])

iv = bytes([
    # partone IV
    0x0d, 0x0e, 0x0f, 0x10,

    # parttwo2 (calculated)
    0xf7, 0x45, 0xc7, 0xc9,

    # partthree2 (dump from frida)
    0x57, 0x51, 0xd3, 0xdd, 0x5f, 0x59, 0xda, 0xc4
])

# flag
enc_b64 = 'aZ/KF0GsnN81j5XStQyKz3vXtktTVN5zFqy5lwTmub6fx5w70c+p08O0OWcn/9nh'
ciphertext = base64.b64decode(enc_b64)

# decrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
flag = unpad(plaintext, 16)

print(flag.decode())
```

Flag: **`HTB{It's_great_to_puzzle_the_pieces}`**

I hope you found it useful (: