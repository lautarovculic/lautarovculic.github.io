![[overreact1.png]]
**Difficult:** Very Easy
**Category**: Mobile
**OS**: Android (SDK 29)

**Description**: Some web developers wrote this fancy new app! It’s really cool, isn’t it?

---

I can’t see **any functions**.
Let’s inspect the source code with **jadx**.

After see the **source code**, I look the **assets folder** and there are a **file**
```bash
index.android.bundle
```

And we can see an **Javascript code** **ofuscated**.
Let’s go to [https://prettier.io](https://prettier.io)
And paste the **code**.

At the **end**, we can see:
```javascript
function (g, r, i, a, m, e, d) {
    Object.defineProperty(e, "__esModule", { value: !0 }),
      (e.myConfig = void 0);
    var t = {
      importantData: "baNaNa".toLowerCase(),
      apiUrl: "https://www.hackthebox.eu/",
      debug: "SFRCezIzbTQxbl9jNDFtXzRuZF9kMG43XzB2MzIyMzRjN30=",
    };
    e.myConfig = t;
  },
  400,
  [],
);
```

If we decode the **base64** string
```bash
echo 'SFRCezIzbTQxbl9jNDFtXzRuZF9kMG43XzB2MzIyMzRjN30=' | base64 -d
```

Output:
```bash
HTB{23m41n_c41m_4nd_d0n7_0v32234c7}
```
We get the flag.

I hope you found it useful (: