**Description**: Welcome to Quackify, a music streaming application with premium features locked behind a license validation system. Your mission is to unlock premium access  to get the flag.

**Link**: https://www.mobilehackinglab.com/course/lab-quackify-mhc

![[mhl-quackify1.png]]

Install an **IPA** file can be difficult. So, for make it more easy, I made a YouTube video with the process using **Sideloadly**. **LINK**: [https://www.youtube.com/watch?v=YPpo9owRKGE](https://www.youtube.com/watch?v=YPpo9owRKGE)

Once you have the app installed, let's proceed with the challenge. **unzip** the **`.ipa`** file.
### Clarification
Since I don't have access to the challenge device, **the final flag will be created in the last step of the writeup** as a practical example.
### Recon
This application is a radio app, and by default, **we have the free license**. This *allows us to listen to the radio station for 10 seconds*.

After those 10 seconds, a pop-up will appear to **Upgrade to Premium**.

There are two options:

- License URL: We can serve a **local server** with the **`license.lic`** file. Then, downloading that the app will process the license file. 

- License Key: We can activate the Premium account entering the license key.

We will use the path of **License URL**.

For that, I'll search for **strings** in the **binary file** `quackify`.
```bash
( strings -a -n 4 -t x quackify; strings -a -e l -n 4 -t x quackify ) \
| grep -Ei 'license|premium|trial|subscribe|subscription|upgrade|unlock|entitle|key|serial|token|signature|hmac|sha(1|256|512)|md5|rsa|ecc|seckey|sec(item|trust)|validate|verify|expires|valid|plist|json|url|http|https|quack' \
| sort -fu | tee quackify_hits.txt
```
Output:
```bash
199d0 _TtC8quackify16LicenseGenerator
199f4  License file opened:
19a13  Failed to process license file:
19a44  License processing result:
19a70 PREMIUM ACTIVATED
19a94  License processed:
19ab4  Premium license activated!
19b24  Premium license detected and activated!
19b50 http://localhost:8001/license.lic
19b83  Invalid license server URL
19ba0 Invalid license server URL
19bc4  Attempting to fetch license from:
19bf0 v32@?0@"NSData"8@"NSURLResponse"16@"NSError"24
19c23  No data received from license server
19c53  License file downloaded (
19c73  Failed to save downloaded license:
19cc4  Remote license processing result:
19cf4  Remote license processed:
19d14  Remote premium license activated!
19d40 Premium license activated!
19d64  Extracted flag from remote license:
19db0 Failed to save downloaded license:
19de0 No data received from license server
19e10 https://quackify-license-worker.arnotstacc.workers.dev/
19ea3  Invalid license file:
19ec4  Premium license activated successfully!
19f10 premium-license.txt
19f33  Could not read premium license file:
19f64  Premium license content loaded for copy button:
19fa0 /validate-license
19fc3  Invalid validation service URL
19ff0 application/json
1a013  Failed to prepare validation request
1a043  No response from validation service
1a073  Failed to parse validation response
1a0a3  Invalid license key
1a100 https://ice1.somafm.com/defcon-128-mp3
1a133  Invalid stream URL
1a1b3  Free preview ended. Upgrade to premium for unlimited streaming!
1a220 Premium: Unlimited streaming
1a260 https://somafm.com/defcon/
1a2a0 License Server URL:
1a2c0 Enter license server URL
1a2e0 Enter a URL to download and process a license file
1a370 Download License
1a393  License processing failed:
1a3b3  License processed:
1a3d0 Premium license activated
1a3f0 Activate Premium
1a410 Premium License Key:
1a430 Enter your license key
1a450 Enter your premium license key
1a470 Upgrade to Premium
1a490 Enjoy unlimited streaming with premium features!
1a4d0 _TtC8quackify7License
1a516 isValid
1a530 _TtC8quackify11LicenseFile
1a554  Attempting to deserialize license file...
1a583  Deserialization error:
1a5a0 Error processing license:
1a5c0 solution.License
1a5e0 test_license.License
1a600 create_compatible_license.License
1a630 License file processed but returned nil
1a680 License file processed (unexpected type)
1a6b4  License deserialized: userType=
1a6e0 License processed but user is not premium
1a710 PREMIUM ACTIVATED - Welcome premium user!
1a744  Checking license at:
1a764  License file not found
1a780 quackify.License
1a7a3  Could not read premium license file
1a7d3  Premium license activated!
1a850 _TtC8quackifyP33_48B8688DFAC18246C0A0E557C1B756F719ResourceBundleClass
1a971 /System/Library/CoreServices/SystemVersion.plist
1aa90 quackify
1aaa0 LicenseGenerator
1aae1 quackifyApp
1ac70 PremiumPromptView
1aded License
1adf5 LicenseFile
1ecce AFG_
1f979 _isPremium
1f990 _isPremium
1fa00 _showPremiumPrompt
1fa20 _premiumServerURL
1fa32 _premiumKey
1fa40 _selectedPremiumOption
1fa60 _isValidatingLicense
1fac0 CLOUDFLARE_WORKER_URL
1fadb _serverURL
1faf6 _isValidating
1fb43 _licenseURL
1fb8b isValid
1fe34 JSONObjectWithData:options:error:
1fe84 URLsForDirectory:inDomains:
1feab copyItemAtURL:toURL:error:
1feed dataTaskWithURL:completionHandler:
1ff10 dataWithJSONObject:options:error:
1ff32 decodeBoolForKey:
1ff44 decodeObjectForKey:
1ff75 encodeBool:forKey:
1ff88 encodeObject:forKey:
1ffec initWithURL:
1fff9 invalidate
20004 loadData:MIMEType:characterEncodingName:baseURL:
20063 removeItemAtURL:error:
20115 setObject:forKey:
```

Based in the output, I notice this valuable strings:

- `quackify.License`

- `LicenseGenerator`

- `LicenseFile`

- `_isPremium`

- `isValid`

- `presentUpgrade`

After search for this strings in **Ghidra**, I did't find nothing useful.

So we'll use the *best tool out there for performing static analysis on iOS*, which is **`ipsw`**.

Let's extract all Swift **metadata contained in the Mach-O binary** (`quackify` in this case).
```bash
ipsw swift-dump Payload/quackify.app/quackify --demangle
```
`--demangle` takes “*mangled*” Swift symbols (e.g. `_TtC8quackify16LicenseGenerator`) and *converts them to their human* form (`quackify.LicenseGenerator`).

Output:
```json
[...]
[...]
class quackify.License: NSObject {
  /* fields */
    var userType: String
    var isValid: Swift.Bool
    var extractedFlag: String?
  /* methods */
    // <stripped> func userType.getter
    // <stripped> func userType.setter
    // <stripped> func userType.modify
    // <stripped> func isValid.getter
    // <stripped> func isValid.setter
    // <stripped> func isValid.modify
    // <stripped> func extractedFlag.getter
    // <stripped> func extractedFlag.setter
    // <stripped> func extractedFlag.modify
    // <stripped> static func init
    // <stripped> static func init
    func sub_100017068 // method (instance)
}
[...]
[...]
```

But `quackify.License` what is?

It's a **Class**!
```swift
class quackify.License: NSObject {
    var userType: String
    var isValid: Bool
    var extractedFlag: String?
    ...
}
```
It confirms this because it inherits from **`NSObject`** which *only classes can do this*.

And these variables are the most important for **craft our license**.
### Crafting the License
We need use **Swift** for compile the license, and then, generate that.
```swift
import Foundation

final class License: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool = true
    let userType: String
    let isValid: Bool
    let extractedFlag: String?

    init(userType: String, isValid: Bool, extractedFlag: String?) {
        self.userType = userType
        self.isValid = isValid
        self.extractedFlag = extractedFlag
        super.init()
    }
    required init?(coder aDecoder: NSCoder) {
        self.userType = (aDecoder.decodeObject(forKey: "userType") as? String) ?? "free"
        self.isValid = aDecoder.decodeBool(forKey: "isValid")
        self.extractedFlag = aDecoder.decodeObject(forKey: "extractedFlag") as? String
        super.init()
    }
    func encode(with aCoder: NSCoder) {
        aCoder.encode(self.userType, forKey: "userType")
        aCoder.encode(self.isValid, forKey: "isValid")
    }
}

func emit(module: String, secure: Bool, out: String) throws {
    let lic = License(userType: "premium", isValid: true, extractedFlag: nil)

    let arch: NSKeyedArchiver
    if secure {
        arch = NSKeyedArchiver(requiringSecureCoding: true)
    } else {
        arch = NSKeyedArchiver(requiringSecureCoding: false)
    }
    // map local class with app class
    arch.setClassName("\(module).License", for: License.self)
    arch.encode(lic, forKey: NSKeyedArchiveRootObjectKey)
    arch.finishEncoding()
    try arch.encodedData.write(to: URL(fileURLWithPath: out))
    FileHandle.standardError.write("Wrote \(out) (\(arch.encodedData.count)B) as \(module).License secure=\(secure)\n".data(using: .utf8)!)
}

let args = CommandLine.arguments
let out = (args.dropFirst().first ?? "license.lic")
try emit(module: "quackify", secure: true,  out: out)
```
Then, compile:
```bash
./licgen license.lic
```

Serve the `.lic` file in a **Python server**:
```bash
python3 -m http.server 8080
```
And then just download the license!

![[mhl-quackify2.png]]

But **where's the flag**?

- In the **original lab**, the *app activates premium and sets the flag UI in the same flow* (remote download → parse → `extractedFlag` → `_flagContent/_showCopyButton`).

- On **your physical device**, you're **activating premium with a `.lic` file of the `quackify.License` class (correct)**, but that path doesn't populate `_flagContent` or touch the "*Copy button*" If you instead load a `.lic` file of `solution.License` or a `premium-license.txt` file, it does set the flag... but that flow doesn't show premium. They're two separate paths (intentional).

We just need **create the `premium-license.txt`** file and put into the **Sandbox application**. In the **`Document`** directory.

Let's **find this sandbox**:
```bash
cd /var/mobile/Containers/Data/Application/
```

Then:
```bash
grep -R "com.mobilehackinglab.quackify" /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist
```

And there is the UUID in my case:
```bash
 /var/mobile/Containers/Data/Application/DEAC709F-9333-48F1-AF64-8C2F291D8290/
```

List the `.lic` file with `tree` command:
```bash
Documents
`-- premium.lic

0 directories, 1 file
```

Inside just create the `.txt`:
```bash
echo 'MHC{1337-dummy-flag}' > premium-license.txt
```
Permissions:
```bash
chown mobile:mobile premium-license.txt
```

**Download** again the **`license.lic`** file and now the **flag must be appear**:
![[mhl-quackify3.png]]

I hope you found it useful (:
