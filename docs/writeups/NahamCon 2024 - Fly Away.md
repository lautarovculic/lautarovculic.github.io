**Description**: Lenny Kravitz lovers, this new app cleverly named “*Fly Away!*” can give you random lines from one of his most popular songs. Can you figure out how the songs are being sent to the app?

**Download**: https://lautarovculic.com/my_files/flyaway.apk

![[nahamCon2024_flyaway1.png]]

Install the **APK** with **ADB**
```bash
adb install -r flyaway.apk
```

This app was made in **reFlutter**. You need install it for proceed with this challenge.
Once you install **reFlutter**, run
```bash
reflutter flyaway.apk
```

Then, choose `2. Display absolute code offset for functions` and set your **machine IP**.
This will drop a file named `release.RE.apk`.
Let's create a **key** for the *sign* process.

```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```
**Align** with *zipalign*
```bash
/usr/lib/jvm/java-22-openjdk/build-tools/34.0.0/zipalign -v -p 4 release.RE.apk release-re-align.apk
```

Then, **sign** the apk
```bash
/usr/lib/jvm/java-22-openjdk/build-tools/34.0.0/apksigner sign --ks name.keystore --ks-key-alias alias --ks-pass pass:lautaro --key-pass pass:lautaro --out flyaway-signed.apk release-re-align.apk
```

The final apk is `flyaway-signed.apk`.
Let's install again in our device
```bash
adb install flyaway-signed.apk
```

This will drop a file in **sandbox** app directory, we go with `adb shell` here `/data/data/com.nahamcon2024.flyaway/`.

Then, we can see this file `dump.dart`.
Let's pull to **our machine**
![[nahamCon2024_flyaway2.png]]
**NOTE**:
If you have a **physical device** (like me) you need move *as root* to `sdcard` directory for pulling files as you can see in the image.

We can see in the `dump.dart` the method `decryptIntegrityCheck` (In you case, it may vary), depends in some special case this **may** differ.
![[nahamCon2024_flyaway3.png]]

`"method_name":"decryptIntegrityCheck","offset":"0x0000000000059484"`
The **reFlutter** people have this *javascript* script for **frida**:
```javascript
//frida -U -f <package> -l frida.js

function hookFunc() {

    var dumpOffset = '0x20801C' // _kDartIsolateSnapshotInstructions + code offset

    var argBufferSize = 150

    var address = Module.findBaseAddress('libapp.so') // libapp.so (Android) or App (IOS) 
    console.log('\n\nbaseAddress: ' + address.toString())

    var codeOffset = address.add(dumpOffset)
    console.log('codeOffset: ' + codeOffset.toString())
    console.log('')
    console.log('Wait..... ')

    Interceptor.attach(codeOffset, {
        onEnter: function(args) {

            console.log('')
            console.log('--------------------------------------------|')
            console.log('\n    Hook Function: ' + dumpOffset);
            console.log('')
            console.log('--------------------------------------------|')
            console.log('')

            for (var argStep = 0; argStep < 50; argStep++) {
                try {
                    dumpArgs(argStep, args[argStep], argBufferSize);
                } catch (e) {

                    break;
                }

            }

        },
        onLeave: function(retval) {
            console.log('RETURN : ' + retval)
            dumpArgs(0, retval, 150);
        }
    });

}

function dumpArgs(step, address, bufSize) {

    var buf = Memory.readByteArray(address, bufSize)

    console.log('Argument ' + step + ' address ' + address.toString() + ' ' + 'buffer: ' + bufSize.toString() + '\n\n Value:\n' +hexdump(buf, {
        offset: 0,
        length: bufSize,
        header: false,
        ansi: false
    }));

    console.log('')
    console.log('----------------------------------------------------')
    console.log('')
}

setTimeout(hookFunc, 1000)
```

So we need get the `_kDartIsolateSnapshotInstructions` from `libapp.so`.
Let's decompile with **apktool** the **reflutter apk** and let's found the `libapp.so` file:
![[nahamCon2024_flyaway4.png]]
Then
```bash
readelf -Ws libapp.so | grep _kDartIsolateSnapshotInstructions
```
Output:
```bash
2: 0000000000176940 0x2444e0 OBJECT  GLOBAL DEFAULT    7 _kDartIsolateSnapshotInstructions
```

The value that we need is `0000000000176940`.
So, **according to the script** that **reFlutter** give us, we need make this sum `0x176940 + 0x59484`

Which result in `0x1D5DC4`
Modify `0x20801C` in the code by `0x1D5DC4`. Then, run the script with **frida**.

We will get the flag.

Flag: **`flag{b54c3c4aeb37acaa5702ba835237220}`**

Also, if we **set up** burpsuite as **reFlutter** recommends, setting the **listener** in **8083** port, and in the **request handling** tab, check for *support invisible proxying*. You can get the **another flag** in the response.

Flag: **`flag{594f480d47ec7e0a32a71a6643922}`**

I hope you found it useful (: