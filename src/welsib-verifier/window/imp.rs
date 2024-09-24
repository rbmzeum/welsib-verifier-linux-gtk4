use std::cell::RefCell;
use std::fs::File;

use adw::subclass::prelude::*;
use adw::{prelude::*, NavigationSplitView, HeaderBar};
use gio::Settings;
use glib::subclass::InitializingObject;
use gtk::glib::SignalHandlerId;
use gtk::glib::subclass::Signal;
use gtk::{gio, glib, CompositeTemplate, Entry, FilterListModel, ListBox, Stack, TextView};
use std::cell::OnceCell;

use once_cell::sync::Lazy;

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

fn safe_decode(str: &String) -> Vec<u8> {
    general_purpose::URL_SAFE_NO_PAD.decode(str).unwrap()
}

fn vec2hex(data: Vec<u8>) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn hex2vec(data: &str) -> Vec<u8> {
    data.as_bytes()
    .chunks(2)
    .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
    .collect::<Vec<u8>>()
}

fn decode(str: &String) -> Vec<u8> {
    general_purpose::STANDARD_NO_PAD.decode(str).unwrap()
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

// ANCHOR: struct
// Object holding the state
#[derive(CompositeTemplate, Default)]
#[template(resource = "/ru/welsib/verifier/window.ui")]
pub struct Window {
    pub settings: OnceCell<Settings>,

    #[template_child]
    pub headerbar: TemplateChild<HeaderBar>,

    #[template_child]
    pub content: TemplateChild<TextView>,

    #[template_child]
    pub signature: TemplateChild<TextView>,

    #[template_child]
    pub public_key: TemplateChild<TextView>,

    #[template_child]
    pub status_success: TemplateChild<adw::StatusPage>,

    #[template_child]
    pub status_failed: TemplateChild<adw::StatusPage>,
}
// ANCHOR_END: struct

// ANCHOR: object_subclass
// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for Window {
    // `NAME` needs to match `class` attribute of template
    const NAME: &'static str = "WelsibVerifierWindow";
    type Type = super::Window;
    type ParentType = adw::ApplicationWindow;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();

        klass.install_action("verify", None, |win, _, _| {
            let buffer = win.imp().content.get().buffer();
            let binding = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
            let content = binding.as_str();
            // println!("Content: {}\n{:?}", &content, &content.as_bytes());

            let buffer = win.imp().signature.get().buffer();
            let binding = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
            let signature = binding.as_str();
            // println!("Signature: {}", &signature);

            let buffer = win.imp().public_key.get().buffer();
            let binding = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
            let public_key = binding.as_str();
            // println!("Public key: {}", &public_key);

            unsafe {
                let hash = digest(content.as_bytes());
                // println!("Hash: {}", &vec2hex(hash.clone()));

                let is_valid_content = verify(&hash, &hex2vec(signature), &hex2vec(public_key));
                // println!("Is valid content: {}", &is_valid_content);

                // Доказательство использования не тестовой версии библиотеки при создании подписи signature
                let is_not_test_signature = is_not_test_signature_proof(&hex2vec(signature));
                // println!("Is not test signature: {}", &is_not_test_signature);

                let title_test = if is_not_test_signature {""} else {", и ОСТОРОЖНО, ключь тестовый"};
                if is_valid_content {
                    win.imp().status_success.set_title(["Подпись верна", title_test].concat().as_str());
                } else {
                    win.imp().status_failed.set_title(["Подпись НЕ верна", title_test].concat().as_str());
                }

                win.imp().status_success.set_visible(is_valid_content);
                win.imp().status_failed.set_visible(!is_valid_content);
            }

            // println!("Verify button has been clicked!");
        });
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}
// ANCHOR_END: object_subclass

// ANCHOR: object_impl
// Trait shared by all GObjects
impl ObjectImpl for Window {

    fn constructed(&self) {
        // Call "constructed" on parent
        self.parent_constructed();

        // Setup
        let obj = self.obj();
        obj.setup_callbacks();
    }
}
// ANCHOR_END: object_impl

// Trait shared by all widgets
impl WidgetImpl for Window {}

// ANCHOR: window_impl
// Trait shared by all windows
impl WindowImpl for Window {
}
// ANCHOR_END: window_impl

// Trait shared by all application windows
impl ApplicationWindowImpl for Window {}

// Trait shared by all adwaita application windows
impl AdwApplicationWindowImpl for Window {}
