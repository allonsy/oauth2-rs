# oauth2-rs with curl 0.3
A fork of [oauth2-rs](https://github.com/alexcrichton/oauth2-rs)

* However, I have support for the newest versions of the dependencies, including `curl` version `0.3.0` and url version `1.1.1`.
* The interface is exactly the same as the base repository

As an example, follow the example here:
```rust
extern crate rustc_serialize;
extern crate oauth2;

use rustc_serialize::json;
use std::fs::File;
use std::io::Read;
/* Secrets.json sample contents:
{
  "client_id": "abcde",
  "client_secret": "efgab",
  "auth_url": "https://github.com/login/oauth/authorize",
  "token_url": "https://github.com/login/oauth/access_token"
}
*/
let mut f = File::open("secrets.json").unwrap();
let mut read_str = String::new();
let _ = f.read_to_string(&mut read_str);
let sec : Secret = json::decode(&read_str).unwrap();

let mut conf = oauth2::Config::new(
    &sec.client_id,
    &sec.client_secret,
    &sec.auth_url,
    &sec.token_url
);
conf.scopes = vec!["repo".to_owned()];
let url = conf.authorize_url("v0.0.1 gitbot".to_owned());
println!("please visit this url: {}", url);

let mut user_code = String::new();
let _ = std::io::stdin().read_line(&mut user_code).unwrap();
user_code.pop();
let tok = conf.exchange(user_code).unwrap();
println!("access code is: {}", tok.access_token);
```

## Contributing
* I gladly accept all PRs
* Please feel free to submit any issues for issues and/or feature requests
