/*
// サンプルcurlコード
// for "secret" of HS256
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjIwMDAwMDAwMDB9.Li-7bx277Fi2D4e0rau9BrXijaZOivcct0aOWVQlrHs" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
// for "random_secret" of HS256
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjIwMDAwMDAwMDB9.A0aUwHZGPqXOfk_wFbFC4yK6teERSFmMxjGeSd-wKYQ" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
*/

use crate::globals::*;
use hyper::{Body, Response, StatusCode};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

// TODO: HMAC_SECRETは扱い方を考える。設定ファイルで与えるべきか。ES256等への対応も必要。

// TODO: jwtのpayload定義。そもそもここはexpだけで良いかもしれないが、ユーザ特定したい可能性もある？
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  sub: String,
  name: String,
  iat: usize,
  exp: usize,
}

pub fn authenticate(globals: &Globals, headers: &hyper::HeaderMap) -> Result<(), Response<Body>> {
  println!("auth::authenticate, {:?}", headers);

  let headers_map = headers.get(hyper::header::AUTHORIZATION);
  let res = match headers_map {
    None => {
      println!("No authorization header");
      Err(StatusCode::BAD_REQUEST)
    }
    Some(auth_header) => {
      if let Ok(s) = auth_header.to_str() {
        let v: Vec<&str> = s.split(" ").collect();
        if "Bearer" == v[0] && v.len() == 2 {
          verify_jwt(globals, v[1])
        } else {
          println!("Invalid authorization header format");
          Err(StatusCode::BAD_REQUEST)
        }
      } else {
        println!("Invalid authorization header format");
        Err(StatusCode::BAD_REQUEST)
      }
    }
  };
  if let Err(e) = res {
    Err(Response::builder().status(e).body(Body::empty()).unwrap())
  } else {
    Ok(())
  }
}

fn verify_jwt(globals: &Globals, jwt: &str) -> Result<(), StatusCode> {
  println!("auth::verify_jwt {:?}", jwt);
  // println!("{:?}", globals.hmac_secret);
  // `token` is a struct with 2 fields: `header` and `claims` where `claims` is your own struct.
  // TODO: Support public key based authentication like ES256 in addition to HS256
  let token = decode::<Claims>(
    &jwt,
    &DecodingKey::from_secret(globals.hmac_secret.as_ref()),
    &Validation::default(),
  );
  if let Ok(_) = token {
    println!("Valid token: {:?}", token);
    Ok(())
  } else {
    println!("Invalid token");
    Err(StatusCode::FORBIDDEN)
  }
}
