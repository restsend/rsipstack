use crate::prelude::*;
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
        let base = self.hash_value(format!(
            "{}:{}:{}",
            self.username, self.realm, self.password
        ));
        match self.algorithm {
            // RFC 2617 §3.2.2.2 / RFC 7616: with the `-sess` algorithms HA1 is
            // a session key derived per response: H(H(A1):nonce:cnonce).
            Algorithm::Md5Sess | Algorithm::Sha256Sess | Algorithm::Sha512Sess => {
                let cnonce = match self.qop {
                    Some(AuthQop::Auth { cnonce, .. }) | Some(AuthQop::AuthInt { cnonce, .. }) => {
                        cnonce.as_str()
                    }
                    None => "",
                };
                self.hash_value(format!("{}:{}:{}", base, self.nonce, cnonce))
            }
            _ => base,
        }
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

#[cfg(test)]
mod tests {
    use super::DigestGenerator;
    use crate::sip::headers::auth::{Algorithm, AuthQop};
    use crate::sip::{Method, Uri};

    /// Golden vectors computed with an independent implementation
    /// (`hashlib`) for the `-sess` session-key derivation
    /// HA1 = H(H(A1):nonce:cnonce) (RFC 2617 §3.2.2.2, RFC 7616 §5).
    #[test]
    fn digest_generator_derives_sess_ha1_and_hashes_nc_as_hex() {
        let qop = AuthQop::Auth {
            cnonce: "client-nonce".to_string(),
            nc: 1,
        };
        let uri = Uri::try_from("sip:ims.test").unwrap();
        let cases = [
            (Algorithm::Md5Sess, "b203ed42ed95cad7b8371abbc5879504"),
            (
                Algorithm::Sha256Sess,
                "6b97a5373f10cdfba9bd3e2d572dfa17eb5d801ca779503bef1415b936f34cbe",
            ),
        ];
        for (algorithm, expected) in cases {
            let response = DigestGenerator {
                username: "alice",
                password: "secret",
                nonce: "noncevalue",
                uri: &uri,
                realm: "ims.test",
                method: &Method::Register,
                qop: Some(&qop),
                algorithm,
            }
            .compute();
            assert_eq!(response, expected, "{algorithm:?}");
        }
    }
}
