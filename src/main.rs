// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use openpgp::cert::prelude::*;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use std::io::Write;
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Document, HtmlTextAreaElement};

fn log(text: &str) {
    web_sys::console::log_1(&text.into())
}

fn textarea_value(document: &Document, id: &str) -> String {
    let elem = document
        .get_element_by_id(id)
        .unwrap()
        .dyn_into::<HtmlTextAreaElement>()
        .unwrap();
    elem.value()
}

fn set_result(document: &Document, value: &str) {
    let elem = document
        .get_element_by_id("result")
        .unwrap()
        .dyn_into::<HtmlTextAreaElement>()
        .unwrap();
    elem.set_value(value);
}

fn status(document: &Document, new: &str) {
    let elem = document.get_element_by_id("status").unwrap();
    elem.set_text_content(Some(new));
}

/// Plumbing to read the various <textarea>s and output the result
fn run_encryption(document: &Document) -> Result<()> {
    // Blank the current result
    status(document, "Encrypting...");
    set_result(document, "");
    let public_key = textarea_value(document, "public-key");
    log(&format!("public key is: {}", &public_key));
    let cert = Cert::from_str(&public_key)?;

    let policy = StandardPolicy::new();

    let mut ciphertext = Vec::new();
    let secret = textarea_value(document, "secret");
    encrypt(&policy, &mut ciphertext, &secret, &cert)?;

    let encrypted = String::from_utf8(ciphertext)?;
    set_result(document, &encrypted);
    Ok(())
}

fn main() -> Result<()> {
    console_error_panic_hook::set_once();
    let document = web_sys::window().unwrap().document().unwrap();
    let closure = Closure::wrap(Box::new(move || {
        let document = web_sys::window().unwrap().document().unwrap();
        match run_encryption(&document) {
            Ok(_) => status(&document, "Done!"),
            Err(err) => status(&document, &format!("Error: {}", err)),
        };
    }) as Box<dyn Fn()>);
    let button = document.get_element_by_id("go").unwrap();
    button
        .add_event_listener_with_callback("click", closure.as_ref().unchecked_ref())
        .expect("failed to install click handler");
    closure.forget();
    Ok(())
}

/// Encrypts the given message.
/// Copied from https://gitlab.com/sequoia-pgp/sequoia/blob/main/openpgp/examples/generate-encrypt-decrypt.rs
fn encrypt(
    p: &dyn Policy,
    sink: &mut (dyn Write + Send + Sync),
    plaintext: &str,
    recipient: &openpgp::Cert,
) -> openpgp::Result<()> {
    let recipients = recipient
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);
    let message = Armorer::new(message).build()?;

    // We want to encrypt a literal data packet.
    let message = Encryptor::for_recipients(message, recipients).build()?;

    // Emit a literal data packet.
    let mut message = LiteralWriter::new(message).build()?;

    // Encrypt the data.
    message.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    message.finalize()?;

    Ok(())
}
