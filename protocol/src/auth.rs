use std::fmt::{Debug, Formatter};

use totp_rs::{Algorithm, TotpUrlError, TOTP};

pub struct Auth {
    totp: TOTP,
}

impl Debug for Auth {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("totp", &self.totp.to_string())
            .finish()
    }
}

impl Auth {
    pub fn new(
        token_secret: String,
        account_name: impl Into<Option<String>>,
    ) -> Result<Self, TotpUrlError> {
        Ok(Self {
            totp: TOTP::new(
                Algorithm::SHA512,
                8,
                1,
                30,
                token_secret.into_bytes(),
                None,
                account_name
                    .into()
                    .unwrap_or_else(|| "default_account".to_string()),
            )?,
        })
    }

    pub fn generate_token(&self) -> String {
        self.totp
            .generate_current()
            .unwrap_or_else(|err| panic!("generate current token failed: {}", err))
    }

    pub fn auth(&self, token: &str) -> bool {
        self.totp.check_current(token).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        const TOKEN_SECRET: &str = "testtesttesttest";
        const ACCOUNT_NAME: Option<String> = None;

        let token_generator = Auth::new(TOKEN_SECRET.to_string(), ACCOUNT_NAME.clone()).unwrap();
        let totp = TOTP::new(
            Algorithm::SHA512,
            8,
            1,
            30,
            TOKEN_SECRET.as_bytes().to_vec(),
            None,
            ACCOUNT_NAME.unwrap_or_else(|| "default_account".to_string()),
        )
        .unwrap();

        let token = token_generator.generate_token();
        let expect = totp.generate_current().unwrap();

        assert_eq!(token, expect);
    }

    #[test]
    fn check_auth() {
        let secret = "test-secrettest-secret".to_string();
        let account_name = "test".to_string();

        let totp = TOTP::new(
            Algorithm::SHA512,
            8,
            1,
            30,
            secret.clone().into_bytes(),
            None,
            account_name.clone(),
        )
        .unwrap();

        let auth = Auth::new(secret, account_name).unwrap();

        let token = totp.generate_current().unwrap();

        dbg!(&token);

        assert!(auth.auth(&token));
    }

    #[test]
    fn check_auth_with_different_account_name() {
        let secret = "test-secrettest-secret".to_string();

        let totp = TOTP::new(
            Algorithm::SHA512,
            8,
            1,
            30,
            secret.clone().into_bytes(),
            None,
            "test".to_string(),
        )
        .unwrap();

        let auth = Auth::new(secret, None).unwrap();

        let token = totp.generate_current().unwrap();

        dbg!(&token);

        assert!(auth.auth(&token));
    }
}
