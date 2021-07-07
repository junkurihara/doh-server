/*
// サンプルcurlコード
// for "secret" of HS256
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjI1NjUzNDMyLCJleHAiOjE2NTcxODk0MzJ9.REuGilzx8syXPYdKSpAwxutXtx3HAvfrTh3As1TBUOg" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
// for "random_secret" of HS256
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjI1NjUzNTYwLCJleHAiOjE2NTcxODk1NjB9.vbjO3RKchY1vTfZpERenbAnxGJivQU2VVw6tjhjKqTY" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
// for "ThisIsExampleSecret" (secret_key_hs256.example) of HS256
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjI1NjU1ODI3LCJleHAiOjE2NTcxOTE4Mjd9.Bm19G1-jT8PFKy086svAGTOM8k2Yhsr_FH1KQTwuZ6o" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
// for ES256 (public_key_es256.example)
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzYW1wbGUtc3ViamVjdCIsImlhdCI6MTYyNTY1NTM5NywiZXhwIjoxOTQxMDE1Mzk3fQ._Wxohc89qpyRw0zXMiFh8Gof8UdgOsh2enmmUeWaOLaTAaagqVkxYGCCgj6FqHlGUkm2vrB4JQES370z8xCTdQ" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
*/

use crate::auth_claims::Claims;
use crate::globals::*;
use hyper::{Body, Response, StatusCode};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use log::{debug, error, info, warn};

pub fn authenticate(globals: &Globals, headers: &hyper::HeaderMap) -> Result<(), Response<Body>> {
  debug!("auth::authenticate, {:?}", headers);

  let headers_map = headers.get(hyper::header::AUTHORIZATION);
  let res = match headers_map {
    None => {
      warn!("No authorization header");
      Err(StatusCode::BAD_REQUEST)
    }
    Some(auth_header) => {
      if let Ok(s) = auth_header.to_str() {
        let v: Vec<&str> = s.split(" ").collect();
        if "Bearer" == v[0] && v.len() == 2 {
          verify_jwt(globals, v[1])
        } else {
          error!("Invalid authorization header format");
          Err(StatusCode::BAD_REQUEST)
        }
      } else {
        error!("Invalid authorization header format");
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
  debug!("auth::verify_jwt {:?}", jwt);

  if let Ok(parsed_header) = decode_header(&jwt) {
    let alg = parsed_header.alg;
    if alg != globals.validation_algorithm {
      error!("Invalid algorithm");
      return Err(StatusCode::FORBIDDEN);
    }
    let decoding_key = match globals.get_type() {
      AlgorithmType::HMAC => DecodingKey::from_secret(globals.validation_key.as_ref()),
      AlgorithmType::EC => {
        let ec_key_bytes = globals.validation_key.as_bytes();
        DecodingKey::from_ec_pem(ec_key_bytes).unwrap()
      }
      AlgorithmType::RSA => {
        let rsa_key_bytes = globals.validation_key.as_bytes();
        DecodingKey::from_rsa_pem(rsa_key_bytes).unwrap()
      }
    };
    let verified = decode::<Claims>(&jwt, &decoding_key, &Validation::new(alg));
    if let Ok(_) = verified {
      info!("Valid token: {:?}", verified);
      Ok(())
    } else {
      error!("Invalid token");
      Err(StatusCode::FORBIDDEN)
    }
  } else {
    return Err(StatusCode::FORBIDDEN);
  }
}
