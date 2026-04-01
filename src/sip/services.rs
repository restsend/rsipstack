use crate::sip::{
    headers::auth::{Algorithm, AuthQop},
    headers::typed::Authorization,
    Method, Uri,
};

#[derive(Debug, Clone)]
pub struct DigestGenerator<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub nonce: &'a str,
    pub uri: &'a Uri,
    pub realm: &'a str,
    pub method: &'a Method,
    pub qop: Option<&'a AuthQop>,
    pub algorithm: Algorithm,
}

impl<'a> DigestGenerator<'a> {
    pub fn from(auth: &'a Authorization, password: &'a str, method: &'a Method) -> Self {
        Self {
            username: &auth.username,
            password,
            nonce: &auth.nonce,
            uri: &auth.uri,
            realm: &auth.realm,
            method,
            qop: auth.qop.as_ref(),
            algorithm: auth.algorithm.unwrap_or(Algorithm::Md5),
        }
    }

    pub fn verify(&self, response: &str) -> bool {
        self.compute() == response
    }

    pub fn compute(&self) -> String {
        let value = match self.qop {
            Some(AuthQop::Auth { cnonce, nc }) => format!(
                "{}:{}:{:08x}:{}:{}:{}",
                self.ha1(),
                self.nonce,
                nc,
                cnonce,
                "auth",
                self.ha2()
            ),
            Some(AuthQop::AuthInt { cnonce, nc }) => format!(
                "{}:{}:{:08x}:{}:{}:{}",
                self.ha1(),
                self.nonce,
                nc,
                cnonce,
                "auth-int",
                self.ha2()
            ),
            None => format!("{}:{}:{}", self.ha1(), self.nonce, self.ha2()),
        };
        self.hash_value(value)
    }

    fn ha1(&self) -> String {
        self.hash_value(format!(
            "{}:{}:{}",
            self.username, self.realm, self.password
        ))
    }

    fn ha2(&self) -> String {
        let value = match self.qop {
            None | Some(AuthQop::Auth { .. }) => format!("{}:{}", self.method, self.uri),
            _ => format!(
                "{}:{}:d41d8cd98f00b204e9800998ecf8427e",
                self.method, self.uri
            ),
        };
        self.hash_value(value)
    }

    fn hash_value(&self, value: String) -> String {
        use md5::{Digest, Md5};
        use sha2::{Sha256, Sha512};

        match self.algorithm {
            Algorithm::Md5 | Algorithm::Md5Sess => {
                let mut h = Md5::new();
                h.update(value.as_bytes());
                encode_lower_hex(h.finalize())
            }
            Algorithm::Sha256 | Algorithm::Sha256Sess => {
                let mut h = Sha256::new();
                h.update(value.as_bytes());
                encode_lower_hex(h.finalize())
            }
            Algorithm::Sha512 | Algorithm::Sha512Sess => {
                let mut h = Sha512::new();
                h.update(value.as_bytes());
                encode_lower_hex(h.finalize())
            }
        }
    }
}

fn encode_lower_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}
