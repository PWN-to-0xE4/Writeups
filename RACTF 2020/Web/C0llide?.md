# C0llide?

### Writeup by Segway, 250 points

`A target service is asking for two bits of information that have the same "custom hash", but can't be identical. Looks like we're going to have to generate a collision?`

The challenge page provides the source code for the challenge, which is provided below for reference: 

```js
const bodyParser = require("body-parser")
const express = require("express")
const fs = require("fs")
const customhash = require("./customhash")

const app = express()
app.use(bodyParser.json())

const port = 3000
const flag = "flag"
const secret_key = "Y0ure_g01nG_t0_h4v3_t0_go_1nto_h4rdc0r3_h4ck1ng_m0d3"

app.get('/', (req, res) => {
    console.log("[-] Source view")
    res.type("text")
    return fs.readFile("index.js", (err,data) => res.send(data.toString().replace(flag, "flag")))
})

app.post('/getflag', (req, res) => {
    console.log("[-] Getflag post")
    if (!req.body) {return res.send("400")}
    let one = req.body.one
    let two = req.body.two
    console.log(req.body)
    if (!one || !two) {
        return res.send("400")
    }
    if ((one.length !== two.length) || (one === two)) {
        return res.send("Strings are either too different or not different enough")
    }
    one = customhash.hash(secret_key + one)
    two = customhash.hash(secret_key + two)
    if (one == two) {
        console.log("[*] Flag get!")
        return res.send(flag)
    } else {
        return res.send(`${one} did not match ${two}!`)
    }
})

app.listen(port, () => console.log(`Listening on port ${port}`))
```
In order to get the flag, we need to send a POST request to the `/getflag` endpoint with the parameters `one` and `two` such that they produce the same hash.

Although the challenge description implies that we might need to perform a hash collision, it is not feasible to do so for a custom algorithm. Instead, we can try to figure out a way to get the inputs to the hash function to match.

By looking at the source code, we can come to the following conclusions:

* The parameters passed must be valid JSON data types
* The parameters passed must have a valid length, and have equal length
* The parameters passed must not be equal in type and value (since a strict comparison is being used)
* The parameters passed must form the same string

The key to this challenge is in the strict comparison. Due to Javascript's weak typing, strings can be concatenated with non-string values:
```javascript
>> "hello" + 1
<  "hello1"

>> "hello" + [1]
< "hello1"
```

The implicit string conversion is based on the contents of the value.

If we provide values with different types, but the same content, we should be able to obtain the flag. Since we need data types with a valid length, we can use an array and a string:

```
curl -d '{"one": "1", "two": [1]}' -X POST "http://95.216.233.106:52827/getflag" -H "Content-Type: application/json"
```

(`curl` assumes POST data is in an URL format by default, hence the `Content-Type` header)

This gives us the flag: `ractf{Y0u_R_ab0uT_2_h4Ck_t1Me__4re_u_sur3?}`
