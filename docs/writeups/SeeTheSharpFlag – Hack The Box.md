![[stsflag1.png]]
**Difficult:** Medium
**Category**: Mobile
**OS**: Android

**Description**: I have made a password verification app. If I can remember the password, the app will tell me it is correct. See if you can guess my password.

---

The first step that we need to do is download the **.zip** file and extract the **.apk** with **apktool**
![[stsflag2.png]]

Looking in the app, we no have information
![[stsflag3.png]]
Now it’s time to inspect the source code.

Well..
![[stsflag4.png]]
I think that I need install a Windows VM because we will work with **Xamarin** and **.NET**

### About Xamarin

It’s an open-source platform for building apps for iOS, Android and Windows with **.NET**

A short build process is:
![[stsflag5.png]]
The source code undergoes compilation into Common Intermediate Language (CIL or IL) instructions, which are then stored in Dynamic Link Library (DLL) managed assemblies. Subsequently, the Android package builder amalgamates these assemblies with app resources and additional data, forming an APK package.

Various options and settings exist that can impact the contents of the APK. As an illustration, during the build process, one might opt for the displayed choice in the diagram below to integrate assemblies into native code.
![[stsflag6.png]]
So inspecting the .**dll** files with _dnSpy_, we will just focus in this **.dll**

**SeeTheSharpFlag.dll**

**SeeTheSharpFlag.Android.dll**
![[stsflag7.png]]
We have problems, let’s check the hex info.

The **magic numbers** say that its a **XALZ** file:
![[stsflag8.png]]

Let’s check info about XALZ.
[https://github.com/lz4/lz4](https://github.com/lz4/lz4)
[https://www.revers0.com/posts/xamarin/](https://www.revers0.com/posts/xamarin/)

We discover that the compressor is LZ4, so, I found this script for decompress this **.dll** files
[https://github.com/x41sec/tools/blob/master/Mobile/Xamarin/Xamarin_XALZ_decompress.py](https://github.com/x41sec/tools/blob/master/Mobile/Xamarin/Xamarin_XALZ_decompress.py)

Usage:
```bash
./command SeeTheSharpFlag.dll SeeTheSharpFlagUC.dll
```
![[stsflag9.png]]

Then now we can try open this file with Linux using some plugins for VS code.
![[stsflag10.png]]

Here we can see that the **Button_Clicked** have some interesting points.

This particular function:
![[stsflag11.png]]
The input is compared with the method **streamReader.ReadToEnd** (The decrypt value of encrypt secret value).

And if is **=** then we will receive the “Congratz! You found the secret message”.
**Else**, we receive “_Sorry. Not correct password_”.
With **dnSpy** we can **modify** the **.dll** so, we can manipulate the **.dll** in this case:
![[stsflag12.png]]
**Edit IL Instructions**…

We can see that the call to **System.String::op_Equality**, after, the **brfalse.s** instruction will jump to **ldarg.0** that is the true.
![[stsflag13.png]]

We can flip to true in this case:
![[stsflag14.png]]

![[stsflag15.png]]
Now we change the route from the fail msg, to the success messege. But this isn’t the flag. Just is an “Congratz!” message. So, let’s inspect the source code.

The flag is stored in the **streamReader** so, we can change for any method, for example **array2.ReadToEnd()**
![[stsflag16.png]]
Leave **V_1 (1)** in the **ldloc.s**

Now we have streamReader free, so, we can change the “Congratz” message for the method.

So, we can change **this.SecretOutput.Text** = “_congratz bla lba_” to **streamReader.ReadToEnd()**

Before
![[stsflag17.png]]

After
![[stsflag18.png]]
Now we need save the module, and repack, sign zipalign and install.

The process:
![[stsflag19.png]]

Save the module:
![[stsflag20.png]]

![[stsflag21.png]]
Now we need delete the “**SeeTheSharp.dll**” **original** file from the _extracted APK_.

And remember save the new modified **.dll** like the original name:
![[stsflag22.png]]

![[stsflag23.png]]
Now delete the **APK** in our genymorion device and proceed with the process.

Repacking the APK:
```bash
apktool b com.companyname.seethesharpflag-x86
```

![[stsflag24.png]]
And is necessary **sign** the APK file with **jarsigner**:

But, first, we need generate a keystore:
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

And now:
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore com.companyname.seethesharpflag-x86/dist/com.companyname.seethesharpflag-x86.apk alias
```

![[stsflag25.png]]

And at the end, just need **zipalign**:
```bash
zipalign -p -f 4 com.companyname.seethesharpflag-x86/dist/com.companyname.seethesharpflag-x86.apk seethesharpFLAG.apk
```

![[stsflag26.png]]
Delete the old **.apk** and **install the new** in our android device:

And, open the app. We will see the flag!
![[stsflag27.png]]

I hope you found it useful (: