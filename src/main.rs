use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestInit {
    pub client_public_key: String, // base64(client_public_key)
    pub public_sig_key: String, // base64(public_sig_key)
    pub license_key_hash: String, // base64(hash(hash(license_key)+extract_key_hash))
    pub imei_hash: String, // base64(hash(IMEI+extract_key_hash))
    pub sim_serial_number_hash: String, // base64(hash(SIM_SerialNumber+extract_key_hash))
    pub rustore_token_hash: String, // base64(hash(RuStore_Token+extract_key_hash))
    pub apns_token_hash: String, // base64(hash(APNS_Token+extract_key_hash))
    pub seller_id_hash: String, // base64(hash(Seller_id+extract_key_hash))
    pub control_sum: String, // base64(hash(client_public_key+public_sig_key+license_key_hash+imei_hash+sim_serial_number_hash+rustore_token_hash+seller_id))
}

#[link(name="verify")]
unsafe extern {
    fn digest(data: &[u8]) -> Vec<u8>;
    fn digest_init();
    fn digest_update(bytes: &[u8]);
    fn digest_finalize() -> Vec<u8>;
    fn verify(hash: &Vec<u8>, signature: &Vec<u8>, verifying_key: &Vec<u8>) -> bool;
    fn is_not_test_signature_proof(signature_bytes: &Vec<u8>) -> bool;
    fn activation_proof(request_init_json: &Vec<u8>, multi_signature_bytes: &Vec<u8>) -> bool;
}

fn main() -> std::io::Result<()> {
    unsafe {
        let content = std::fs::read_to_string("test.txt")?;
        println!("Content: {}", &content);

        let signature = std::fs::read("test.txt.sig")?;
        println!("Signature: {}", &vec2hex(signature.clone()));

        let verifying_key = std::fs::read("public.key")?;
        println!("Verifying key: {}", &vec2hex(verifying_key.clone()));

        let hash = digest(content.as_bytes());
        println!("Hash: {}", &vec2hex(hash.clone()));

        let is_valid_content = verify(&hash, &signature, &verifying_key);
        println!("Is valid content: {}", &is_valid_content);

        // Доказательство использования не тестовой версии библиотеки при создании подписи signature
        let is_not_test_signature = is_not_test_signature_proof(&signature);
        println!("Is not test signature: {}", &is_not_test_signature);

        // Доказательство совершения активации с использованием аггрегированной
        // подписи между сервисом и пользователем библиотеки для публичного ключа init_json.client_public_key
        let init_json = std::fs::read("init_json.txt")?;
        let multi_signature_bytes = hex2vec(std::fs::read_to_string("test_agg_signature.hex.txt")?);
        let is_activation = activation_proof(&init_json, &multi_signature_bytes);
        println!("Is activation: {}", &is_activation);

        // Публичный ключ клиента, для которого осуществлено доказательство валидности аггрегированной подписи формируемой при активации библиотеки
        let init_json = std::fs::read_to_string("init_json.txt")?;
        let client_public_key = match serde_json::from_str::<RequestInit>(&init_json) {
            Ok(r) => vec2hex(decode(&r.client_public_key)),
            Err(e) => return Err(e.into())
        };
        println!("Client public key: {}", &client_public_key);
    }

    Ok(())
}

fn safe_decode(str: &String) -> Vec<u8> {
    general_purpose::URL_SAFE_NO_PAD.decode(str).unwrap()
}

fn vec2hex(data: Vec<u8>) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn hex2vec(data: String) -> Vec<u8> {
    data.as_bytes()
    .chunks(2)
    .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
    .collect::<Vec<u8>>()
}

fn decode(str: &String) -> Vec<u8> {
    general_purpose::STANDARD_NO_PAD.decode(str).unwrap()
}