use rand;
use std::vec::Vec;

use super::N;
use super::bigint;
use super::padding;
use super::verification::Key;
use bits;
use digest::{digest, SHA1};
use error::Unspecified;
use untrusted;

/// RSAES-OAEP encryption
pub fn encrypt(
    rng: &rand::SecureRandom, n: untrusted::Input, e: untrusted::Input,
    msg: untrusted::Input) -> Result<Vec<u8>, Unspecified>
{
    let pub_key = Key::from_modulus_and_exponent(
        n, e, bits::BitLength(1024), bits::BitLength(2048), 3)?;
    let msg = msg.as_slice_less_safe();
    let k = pub_key.modulus_len();
    let h_len = SHA1.output_len;
    let m_len = msg.len();
    if m_len.checked_add(2 * h_len + 2).map_or(true, |l| l > k) {
        return Err(Unspecified); // MessageTooLong
    }
    let mut em = vec![0u8; k];
    let l_hash = digest(&SHA1, &[]).as_ref().to_vec();
    let mut ros = vec![0u8; h_len];
    rng.fill(ros.as_mut_slice())?;
    em[1..1+h_len].copy_from_slice(ros.as_slice());
    em[1+h_len..1+2*h_len].copy_from_slice(l_hash.as_slice());
    em[k-m_len-1] = 1u8;
    em[k-m_len..].copy_from_slice(msg);
    let mut db_mask = vec![0u8; k - h_len - 1];
    padding::mgf1(&SHA1, ros.as_slice(), db_mask.as_mut_slice())?;
    for (masked_db_b, mask_b) in em[1+h_len..].iter_mut().zip(db_mask) {
        *masked_db_b ^= mask_b;
    }
    let mut seed_mask = vec![0u8; h_len];
    padding::mgf1(&SHA1, &em[1+h_len..], seed_mask.as_mut_slice())?;
    for (masked_seed_b, mask_b) in em[1..1+h_len].iter_mut().zip(seed_mask) {
        *masked_seed_b ^= mask_b;
    }

    let m = bigint::Elem::from_be_bytes_padded(untrusted::Input::from(&em), &pub_key.n)?;
    unsafe impl bigint::SmallerModulus<N> for N {}
    unsafe impl bigint::NotMuchSmallerModulus<N> for N {}
    let oneRR = bigint::One::newRR(&pub_key.n);
    let m_r = bigint::elem_mul(oneRR.as_ref(), m, &pub_key.n);
    let c = bigint::elem_exp_vartime(m_r, pub_key.e, &pub_key.n);
    c.into_unencoded(&pub_key.n).fit_be_bytes(em.as_mut_slice());
    Ok(em)
}

#[cfg(test)]
mod test {
    use test;
    use super::*;
    use untrusted;

    #[test]
    fn test_rsa_oaep_encrypt() {
        test::from_file("src/rsa/rsa_oaep_encrypt_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let _alg = match digest_name.as_ref() {
                "SHA1" => "",
                _ =>  { panic!("Unsupported digest: {}", digest_name) }
            };

            let n = test_case.consume_bytes("n");
            let n = untrusted::Input::from(&n);

            let e = test_case.consume_bytes("e");
            let e = untrusted::Input::from(&e);

            let msg = test_case.consume_bytes("Plaintext");
            let msg = untrusted::Input::from(&msg);

            let encrypted = test_case.consume_bytes("Ciphertext");

            let salt = test_case.consume_bytes("Random");

            let actual_encrypted = encrypt(
                &test::rand::FixedSliceRandom { bytes: &salt },
                n, e, msg
            ).expect("Failed to encrypt");
            assert_eq!(actual_encrypted.as_slice(), encrypted.as_slice());

            Ok(())
        });
    }
}
