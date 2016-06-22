#![cfg_attr(test, deny(warnings))]
//! A library for making oauth2 requests with updated depencies like curl 0.3.0
//!
//! An example:
//!
//! ```rust,no_run
//! extern crate rustc_serialize;
//! extern crate oauth2;
//!
//! use rustc_serialize::json;
//! use std::fs::File;
//! use std::io::Read;
//! /* Secrets.json sample contents:
//! {
//!   "client_id": "abcde",
//!   "client_secret": "efgab",
//!   "auth_url": "https://github.com/login/oauth/authorize",
//!   "token_url": "https://github.com/login/oauth/access_token"
//! }
//! */
//! let mut f = File::open("secrets.json").unwrap();
//! let mut read_str = String::new();
//! let _ = f.read_to_string(&mut read_str);
//! let sec : Secret = json::decode(&read_str).unwrap();
//!
//! let mut conf = oauth2::Config::new(
//!     &sec.client_id,
//!     &sec.client_secret,
//!     &sec.auth_url,
//!     &sec.token_url
//! );
//! conf.scopes = vec!["repo".to_owned()];
//! let url = conf.authorize_url("v0.0.1 gitbot".to_owned());
//! println!("please visit this url: {}", url);
//!
//! let mut user_code = String::new();
//! let _ = std::io::stdin().read_line(&mut user_code).unwrap();
//! user_code.pop();
//! let tok = conf.exchange(user_code).unwrap();
//! println!("access code is: {}", tok.access_token);
//! ```
//!

extern crate url;
extern crate curl;
#[macro_use] extern crate log;

use url::Url;
use std::sync::{Arc,Mutex};
use std::io::Read;

use curl::easy::{Easy, List};

/// Configuration of an oauth2 application.
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub auth_url: Url,
    pub token_url: Url,
    pub redirect_url: String,
}

/// Represents a Token struct
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct Token {
    /// access token used to authenticate queries
    pub access_token: String,
    /// A vec of scopes
    pub scopes: Vec<String>,
    /// 'bearer', etc...
    pub token_type: String,
}

struct ErrorContainer {
    error : String,
    error_desc : String,
    error_uri : String
}

impl ErrorContainer {
    fn new() -> ErrorContainer {
        ErrorContainer {
            error: String::new(),
            error_desc: String::new(),
            error_uri: String::new()
        }
    }
}

macro_rules! try_error_to_string {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(err) => return Err(::std::convert::From::from(error_to_string(err))),
    });
}


/// Helper trait for extending the builder-style pattern of curl::easy::Easy.
///
/// This trait allows chaining the correct authorization headers onto a curl
/// request via the builder style.
pub trait Authorization {
    fn auth_with(&mut self, token: &Token) -> Result<(), curl::Error>;
}

impl Config {

    /// Generates a new config from the given fields
    pub fn new(id: &str, secret: &str, auth_url: &str,
               token_url: &str) -> Config {
        Config {
            client_id: id.to_string(),
            client_secret: secret.to_string(),
            scopes: Vec::new(),
            auth_url: Url::parse(auth_url).unwrap(),
            token_url: Url::parse(token_url).unwrap(),
            redirect_url: String::new(),
        }
    }

    #[allow(deprecated)] // connect => join in 1.3
    /// Generates an auth url to visit from the infomation in the config struct
    pub fn authorize_url(&self, state: String) -> Url {
        let scopes = self.scopes.connect(",");
        let mut pairs = vec![
            ("client_id", &self.client_id),
            ("state", &state),
            ("scope", &scopes),
        ];
        if self.redirect_url.len() > 0 {
            pairs.push(("redirect_uri", &self.redirect_url));
        }
        let mut url = self.auth_url.clone();

        for (k,v) in pairs {
            url.query_pairs_mut().append_pair(k,v);
        }
        return url;
    }

    /// Given a code (obtained from the authorize_url) and varies by service.
    /// exchange will then make a POST request with the code and attempt to retrieve an access token.
    /// On success, the token is returned as a Result. On failure, a string with an error description
    /// is returned as a Result
    pub fn exchange(&self, code: String) -> Result<Token, String> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("client_id", &self.client_id.clone());
        form.append_pair("client_secret", &self.client_secret.clone());
        form.append_pair("code", &code);
        if self.redirect_url.len() > 0 {
            form.append_pair("redirect_uri", &self.redirect_url.clone());
        }

        let form_str : String = form.finish();
        let post_len = form_str.as_bytes().len();

        let mut easy = Easy::new();
        try_error_to_string!(easy.url(&self.token_url.to_string()));
        let mut list = List::new();
        try_error_to_string!(list.append("Content-Type: application/x-www-form-urlencoded"));
        try_error_to_string!(easy.http_headers(list));
        try_error_to_string!(easy.show_header(true));
        try_error_to_string!(easy.read_function(move |buf| {
            Ok(form_str.as_bytes().read(buf).unwrap_or(0))
        }));
        try_error_to_string!(easy.post(true));
        try_error_to_string!(easy.post_field_size(post_len as u64));

        let token = Token {
            access_token: String::new(),
            scopes: Vec::new(),
            token_type: String::new(),
        };

        let protector = Arc::new(Mutex::new(token));
        let result_ref = protector.clone();
        let error_strings = Arc::new(Mutex::new(ErrorContainer::new()));
        let error_strings_copy = error_strings.clone();

        try_error_to_string!(easy.write_function(move |data| {
            let mut result_token = result_ref.lock().unwrap();
            let mut err_cont = error_strings_copy.lock().unwrap();

            let result_form = url::form_urlencoded::parse(data);
            for(k, v) in result_form.into_iter() {
                match &k[..] {
                    "access_token" => result_token.access_token = (*v).to_owned(),
                    "token_type" => result_token.token_type = (*v).to_owned(),
                    "scope" => {
                        result_token.scopes = v.split(',')
                                        .map(|s| s.to_string()).collect();
                    },
                     "error" => err_cont.error = (*v).to_owned(),
                     "error_description" => err_cont.error_desc = (*v).to_owned(),
                     "error_uri" => err_cont.error_uri = (*v).to_owned(),
                    _ => {}
                }
            }
            return Ok(data.len());
        }));

        try_error_to_string!(easy.perform());

        let resp_code = try_error_to_string!(easy.response_code());
        if resp_code != 200 {
            return Err(format!("expected `200`, found `{}`", resp_code))
        }

        let new_token = protector.lock().unwrap();
        let new_errors = error_strings.lock().unwrap();

        if new_token.access_token.len() != 0 {
            Ok(new_token.clone())
        } else if new_errors.error.len() > 0 {
            Err(format!("error `{}`: {}, see {}", new_errors.error, new_errors.error_desc, new_errors.error_uri))
        } else {
            Err(format!("couldn't find access_token in the response"))
        }
    }
}

fn error_to_string(e : curl::Error) -> String {
    let err_str : &str;
    err_str = if e.is_unsupported_protocol() {
        "Unsupported Protocol!"
    } else if e.is_failed_init() {
        "Failed to initialize"
    } else if e.is_url_malformed() {
        "Url is malformed!"
    } else if e.is_couldnt_resolve_proxy() {
        "Couldn't resolve proxy"
    } else if e.is_couldnt_resolve_host() {
        "Couldn't Resolve host"
    } else if e.is_couldnt_connect() {
        "Couldn't Connect"
    } else if e.is_remote_access_denied() {
        "Remote access is denied"
    } else if e.is_partial_file() {
        "Partial file given"
    } else if e.is_quote_error() {
        "Quote error"
    } else if e.is_http_returned_error() {
        "Http returned error"
    } else if e.is_read_error() {
        "Read error"
    } else if e.is_write_error() {
        "Write Error"
    } else if e.is_upload_failed() {
        "Upload failed"
    } else if e.is_out_of_memory() {
        "Out of memory"
    } else if e.is_operation_timedout() {
        "Timed out"
    } else if e.is_range_error() {
        "Range error"
    } else if e.is_http_post_error() {
        "Http post error"
    } else if e.is_ssl_connect_error() {
        "SSL connect error"
    } else if e.is_bad_download_resume() {
        "Bad download resume error"
    } else if e.is_file_couldnt_read_file() {
        "Cannot read given file"
    } else if e.is_function_not_found() {
        "Cannot find given function error"
    } else if e.is_aborted_by_callback() {
        "Callback aborted error"
    } else if e.is_bad_function_argument() {
        "Bad function argument error"
    } else if e.is_interface_failed() {
        "Interface failed error"
    } else if e.is_too_many_redirects() {
        "Too many redirects error"
    } else if e.is_unknown_option() {
        "Unknown option error"
    } else if e.is_peer_failed_verification() {
        "Peer failed to validate error"
    } else if e.is_got_nothing() {
        "Received nothing error"
    } else if e.is_ssl_engine_notfound() {
        "SSL engine not found error"
    } else if e.is_ssl_engine_setfailed() {
        "SSL engine set failed error"
    } else if e.is_send_error() {
        "Send failed error"
    } else if e.is_recv_error() {
        "Recieve failed error"
    } else if e.is_ssl_certproblem() {
        "SSL certificate problem error"
    } else if e.is_ssl_cipher() {
        "SSL cipher error"
    } else if e.is_ssl_cacert() {
        "SSL CA Cert error"
    } else if e.is_bad_content_encoding() {
        "Bad content encoding error"
    } else if e.is_filesize_exceeded() {
        "Filesize exceeded error"
    } else if e.is_use_ssl_failed() {
        "Use SSL failed error"
    } else if e.is_send_fail_rewind() {
        "Send rewind fail error"
    } else if e.is_ssl_engine_initfailed() {
        "SSL engine init fail error"
    } else if e.is_login_denied() {
        "Login denied error"
    } else if e.is_conv_failed() {
        "Conv failed error"
    } else if e.is_conv_required() {
        "Conv required error"
    } else if e.is_ssl_cacert_badfile() {
        "CA cert bad file error"
    } else if e.is_ssl_crl_badfile() {
        "SSL crl bad file error"
    } else if e.is_ssl_shutdown_failed() {
        "SSL Shutdown failed error"
    } else if e.is_again() {
        "Again error"
    } else if e.is_ssl_issuer_error() {
        "SSL Issuer error"
    } else if e.is_chunk_failed() {
        "Chunk failed error"
    } else {
        "general error"
    };
    return err_str.to_string();
}

/// Given a curl::easy::Easy and a `Token` struct, it adds the Authorization: access_token header
/// to the request. It return curl::Error when adding the header fails.
impl Authorization for curl::easy::Easy{
    fn auth_with(&mut self, token: &Token) -> Result<(), curl::Error> {
        let mut auth_header = List::new();
        let auth_header_text = format!("Authorization: {}", token.access_token);
        let res = auth_header.append(&auth_header_text);
        if res.is_ok() {
            self.http_headers(auth_header)
        } else {
            res
        }
    }
}
