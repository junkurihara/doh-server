use serde::{Deserialize, Serialize};

// TODO: jwtのpayload定義。そもそもここはexpだけで良いかもしれないが、ユーザ特定したい可能性もある？
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  sub: String,
  iat: usize,
  exp: usize,
}
