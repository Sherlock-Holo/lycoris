use totp_rs::{Algorithm, TOTP};

use crate::err::Error;

pub struct TokenGenerator {
    totp: TOTP<String>,
}

impl TokenGenerator {
    pub fn new(
        token_secret: String,
        account_name: impl Into<Option<String>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            totp: TOTP::new(
                Algorithm::SHA512,
                8,
                1,
                30,
                token_secret,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        const TOKEN_SECRET: &str = "testtesttesttest";
        const ACCOUNT_NAME: Option<String> = None;

        let token_generator =
            TokenGenerator::new(TOKEN_SECRET.to_string(), ACCOUNT_NAME.clone()).unwrap();
        let totp = TOTP::new(
            Algorithm::SHA512,
            8,
            1,
            30,
            TOKEN_SECRET.to_string(),
            None,
            ACCOUNT_NAME.unwrap_or_else(|| "default_account".to_string()),
        )
        .unwrap();

        let token = token_generator.generate_token();
        let expect = totp.generate_current().unwrap();

        assert_eq!(token, expect);
    }
}
