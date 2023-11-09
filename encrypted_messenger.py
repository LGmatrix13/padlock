#!/usr/bin/env python

import binascii
import PySimpleGUI as sg
import json
from base64 import b64encode, b64decode

import crypto_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

#
# A class that represents an RSA keypair associated with the name of its
# owner.
#
# Properties:
#   private: The private portion of the keypair.
#       Can be None if we only have the public key.
#
#   public: The public portion of the keypair.
#
#   owner: A string indicating the owner of the key.
#
class KeyringEntry:
    #
    # You can pass either an RSAPrivateKey or RSAPublicKey for "key".
    #
    # If it's a private key, we will extract the corresponding public key and
    # set both properties. Otherwise, we will set only the public key.
    #
    def __init__(self, key, owner):
        self.owner = owner

        if isinstance(key, RSAPrivateKey):
            self.private = key
            self.public = key.public_key()
        elif isinstance(key, RSAPublicKey):
            self.public = key
            self.private = None
        else:
            raise Exception("Unrecognized key type!")

# A list of KeyringEntries (RSA keys) that have been loaded into the app.
keyring = []

#
# Return a list of human-readable drop-down-list entries for all the keys in
# "keyring". Each entry lists the owner's name and whether we have the full
# keypair or just the public key. Examples:
#
#       Jimothy Ronsberg (public + private)
#       Barry Millham (public only)
#
def compute_keylist():
    keylist = []
    for key in keyring:
        entry = key.owner

        if key.private:
            entry += " (public + private)"
        else:
            entry += " (public only)"

        keylist.append(entry)

    return keylist

#
# Add a key entry to "keyring", and update the drop-down list of all the
# keys that have been loaded into the app.
#
# Argument: A KeyringEntry object.
#
def add_keyring_entry(entry):
    keyring.append(entry)

    window["_keylist"].update(values = compute_keylist(),
                              set_to_index = len(keyring) - 1)
    window["_keyToUseLabel"].update(f"Key to use ({len(keyring)} loaded):")

######################################################################
# Define the main window's layout and instantiate it
######################################################################

#sg.theme("gray gray gray") # Leaves all system defaults unchanged
#sg.theme("Dark Amber")
sg.theme("Light Green 5")

# Since we have to specify a monospace font by name for the notepad area and
# benchmark results, define this as a constant so it can be easily changed
# depending on what fonts you actually have available on your system.
#MONOSPACE_FONT = "Courier"
MONOSPACE_FONT = "Courier Prime" # Better font that I have installed on my machine

layout = [
        [sg.Text("Enter plaintext, ciphertext, or public/private key:"),
         sg.Button("Clear"), sg.Push(), sg.Button("Run Benchmarks")],
        [sg.Multiline(size=(100,20), font=(MONOSPACE_FONT, 12),
                      key="_notepad")],
        [sg.Button("Encrypt"), sg.Button("Decrypt"),
         sg.Text("Key to use (0 loaded):", key="_keyToUseLabel"),
         sg.Combo([], size=35, readonly=True, key="_keylist"),
         sg.Button("Generate New Keypair"), sg.Button("Import Key"),
         sg.Button("Export Private Key"), sg.Button("Export Public Key")],
          ]

window = sg.Window("Encrypted Messenger", layout)

######################################################################
# Main event loop for window
######################################################################
while True:
    event, values = window.read()

    # Uncomment for debugging
    #print(f"Event: {event}\nValues:{values}\n")

    if event == sg.WIN_CLOSED:
        break

    elif event == "Clear":
        window["_notepad"].update("")

    elif event == "Encrypt":
        # PySimpleGUI unfortunately doesn't provide a "clean" way to get the
        # numeric index of the currently-selected element in a Combo
        # (drop-down box); all it can do is give us the currently-displayed
        # string, which can be ambiguous if there are multiple elements with
        # the same text. We therefore use the current() method on the
        # underlying Tk widget. (This might not work properly if you try
        # porting this to a different PySimpleGUI backend.)
        selected_idx = window["_keylist"].widget.current()

        if selected_idx not in range(0, len(keyring)):
            # The index is out of bounds. This can happen if no keys have
            # been added to the keyring yet (the call to current() will
            # return -1 if there are no items in the Combo), or (potentially)
            # in case of a program bug.
            sg.popup("No key selected!")
            continue

        # Get the public component of the selected recipient's keypair.
        public_key = keyring[selected_idx].public

        # Encrypt the contents of the notepad area with a randomly-generated
        # AES session key (which in turn is encrypted with RSA so it can be
        # decrypted by the recipient's private key).
        #
        # N.B.: We must encode the notepad contents as a raw byte string
        # (vs. a regular string), because only raw bytes are suitable for
        # input to the encryption functions. We use UTF-8 (Unicode) encoding
        # here to allow non-ASCII characters in messages.
        plaintext = values["_notepad"].encode('utf-8')
        (encrypted_session_key, nonce, ciphertext) = \
                crypto_backend.encrypt_message_with_aes_and_rsa(
                        public_key, plaintext)

        # Package the encrypted session key, nonce, and ciphertext as a JSON
        # object suitable for transmission to the recipient.
        #
        # N.B.: Even though we made a point to use UTF-8 instead of ASCII
        # above for the message itself, it is safe to interpret the
        # byte-string output of b64encode() as simple ASCII, because the
        # base64 alphabet is entirely within the ASCII subset of Unicode (for
        # which UTF-8 and ASCII are identical). I could've just as well
        # specified 'utf-8' here, but this is a good teachable moment to
        # explain the difference between the two...
        packaged_msg = {
                'sessionkey': b64encode(encrypted_session_key).decode('ascii'),
                'nonce': b64encode(nonce).decode('ascii'),
                'ciphertext': b64encode(ciphertext).decode('ascii')
                }
        jsonified = json.JSONEncoder().encode(packaged_msg)

        # Display the JSON in the notepad area.
        window["_notepad"].update(jsonified)

    elif event == "Decrypt":
        # Get the index of the currently-selected key (see comment above
        # under "Encrypt" case).
        selected_idx = window["_keylist"].widget.current()

        if selected_idx not in range(0, len(keyring)):
            # The index is out of bounds. This can happen if no keys have
            # been added to the keyring yet (the call to current() will
            # return -1 if there are no items in the Combo), or (potentially)
            # in case of a program bug.
            sg.popup("No key selected!")
            continue

        # Get the private component of the selected recipient's keypair.
        if not keyring[selected_idx].private:
            sg.popup("We only have the public component of that key.\n"
                     "We can send messages *to* it, but not decrypt "
                     "messages encrypted for it.", title = "Cannot Decrypt")
            continue # Stop processing this event
        private_key = keyring[selected_idx].private

        # Unpackage the notepad area's contents as a JSON object
        # encapsulating the encrypted session key, nonce, and ciphertext.
        try:
            packaged_msg = json.JSONDecoder().decode(values["_notepad"])
        except json.decoder.JSONDecodeError:
            sg.popup("Error: Couldn't parse input as valid JSON.",
                     title = "Error Decrypting Message")
            continue

        # The session key, nonce, and ciphertext are encoded in the JSON as
        # base64 strings; decode them to recover the original byte strings.
        try:
            # N.B.: The b64decode() function doesn't require us to explicitly
            # convert the string inputs into raw byte strings. Unlike
            # b64encode(), it will automatically interpret an input string as
            # ASCII (which is enough for the full base64 alphabet).
            encrypted_session_key = b64decode(
                    packaged_msg['sessionkey'], validate = True)
            nonce = b64decode(packaged_msg['nonce'], validate = True)
            ciphertext = b64decode(packaged_msg['ciphertext'], validate = True)
        except binascii.Error:
            # This will only trigger if characters other than A-Z, a-z, 0-9,
            # +, or / (or = for length padding at the end) are found in the
            # input. Corruptions that produce a legitimate base64 character
            # cannot be detected and will silently change the data.
            #
            # (In the next project, we will learn how to use authenticated
            # encryption to detect corruption! 🙂)
            #
            # Note that we could have set validate = False (the default) in
            # the b64decode() calls above; but this will silently skip the
            # bad characters, which would render the entire rest of the
            # message unreadable (since the ciphertext would become
            # desynchronized with the keystream).
            sg.popup("Error: Invalid characters found in base64 input.",
                     title = "Error Decrypting Message")
            continue

        # Decrypt the session key using RSA, and then the message using AES
        # with the session key and nonce.
        try:
            plaintext = crypto_backend.decrypt_message_with_aes_and_rsa(
                    private_key, encrypted_session_key, nonce, ciphertext)
        except ValueError as e:
            # The cryptography library threw an error trying to decrypt the
            # message. Report it and cancel.
            sg.popup_scrolled(e, title = "Error Decrypting Message")
            continue

        # Display the decrypted message in the notepad area.
        #
        # N.B.: The output of the decryption function is a raw byte string,
        # so we need to convert this back to a UTF-8 string. (We used UTF-8
        # encoding for the input when originally encrypting the message, so
        # this should allow non-ASCII characters to come out the other end
        # unscathed.)
        window["_notepad"].update(plaintext.decode('utf-8'))

    elif event == "Generate New Keypair":
        # Ask the user for the name of the keypair's owner
        owner = sg.popup_get_text(
                "Enter the name of the user associated with this key:",
                title = "Enter Key Owner Name")
        if owner == None:
            # The user clicked "Cancel"; stop processing this event.
            continue

        # rsa_gen_keypair() will return an RSAPrivateKey object, which
        # includes both the public and private components of the keypair.
        keypair = crypto_backend.rsa_gen_keypair()

        # Add the key to the keyring. add_keyring_entry() will automatically
        # update the drop-down list of all the keys that have been loaded
        # into the app (and the "# loaded" label next to it).
        entry = KeyringEntry(keypair, owner)
        add_keyring_entry(entry)

        sg.popup(f"Successfully generated a new keypair for {owner}!",
                 title = "Successfully Generated Keypair")

    elif event == "Import Key":
        # We will interpret the notepad contents as a JSON dictionary that we
        # expect to contain the following entries:
        #   * 'owner': The name of the key's owner; AND
        #   * 'privkey': A PEM serialization of a combined public/private
        #       keypair; OR
        #   * 'pubkey': A PEM serialization of a public key by itself
        #
        # Normally, only one of 'privkey' or 'pubkey' will be present. If
        # both are present, we will use 'privkey' and ignore 'pubkey'.
        try:
            packaged_key = json.JSONDecoder().decode(values["_notepad"])
        except json.decoder.JSONDecodeError:
            sg.popup("Error: Couldn't parse input as valid JSON.",
                     title = "Error Reading Key")
            continue

        # If the 'owner' field is missing, display an error and cancel.
        if 'owner' not in packaged_key:
            sg.popup("Missing field: key owner not specified!",
                     title = "Error Reading Key")
            continue

        # If either the 'privkey' or 'pubkey' field is present, process it
        # accordingly. If neither is present, display an error and cancel.
        try:
            if 'privkey' in packaged_key:
                key = crypto_backend.rsa_deserialize_private_key(
                        packaged_key['privkey'])
            elif 'pubkey' in packaged_key:
                key = crypto_backend.rsa_deserialize_public_key(
                        packaged_key['pubkey'])
            else:
                sg.popup("No public or private key found in input!",
                         title = "Error Reading Key")
                continue
        except ValueError as e:
            # The cryptography library threw an error trying to deserialize
            # the key. Report it and cancel.
            sg.popup_scrolled(e, title = "Error Reading Key")
            continue

        # Add the key to the keyring. add_keyring_entry() will automatically
        # update the drop-down list of all the keys that have been loaded
        # into the app (and the "# loaded" label next to it).
        entry = KeyringEntry(key, packaged_key['owner'])
        add_keyring_entry(entry)

    elif event == "Export Private Key":
        # Get the index of the currently-selected key (see comment above
        # under "Encrypt" case).
        selected_idx = window["_keylist"].widget.current()

        if selected_idx not in range(0, len(keyring)):
            # The index is out of bounds. This can happen if no keys have
            # been added to the keyring yet (the call to current() will
            # return -1 if there are no items in the Combo), or (potentially)
            # in case of a program bug.
            sg.popup("No key selected!")
            continue

        # Serialize the selected key to PEM format. We will serialize the
        # entire keypair (public + private) as a "PRIVATE KEY" block which
        # can be used to re-import the full keypair.
        keyring_entry = keyring[selected_idx]
        if not keyring_entry.private:
            sg.popup("We only have the public component of that key.\n"
                     "Try \"Export Public Key\" to export just the "
                     "public component.", title = "Error Exporting Key")
            continue # Stop processing this event

        key_pem = crypto_backend.rsa_serialize_private_key(
                keyring_entry.private)

        # Package the key in a JSON object that includes the associated owner
        # name.
        packaged_key = {
                'owner': keyring_entry.owner,
                'privkey': key_pem
                }
        jsonified = json.JSONEncoder().encode(packaged_key)

        # Display the JSON in the notepad area.
        window["_notepad"].update(jsonified)

    elif event == "Export Public Key":
        # Get the index of the currently-selected key (see comment above
        # under "Encrypt" case).
        selected_idx = window["_keylist"].widget.current()

        if selected_idx not in range(0, len(keyring)):
            # The index is out of bounds. This can happen if no keys have
            # been added to the keyring yet (the call to current() will
            # return -1 if there are no items in the Combo), or (potentially)
            # in case of a program bug.
            sg.popup("No key selected!")
            continue

        # Serialize the selected key's public component to PEM format.
        keyring_entry = keyring[selected_idx]
        key_pem = crypto_backend.rsa_serialize_public_key(
                keyring_entry.public)

        # Package the key in a JSON object that includes the associated owner
        # name.
        packaged_key = {
                'owner': keyring_entry.owner,
                'pubkey': key_pem
                }
        jsonified = json.JSONEncoder().encode(packaged_key)

        # Display the JSON in the notepad area.
        window["_notepad"].update(jsonified)

    elif event == "Run Benchmarks":
        # Use a custom popup window so we can run the benchmarks in the
        # background and close the popup when they're done.
        popup_window = sg.Window("Running Benchmarks",
                                 [[sg.Text("Running benchmarks, please wait "
                                          "(this will take a bit)...")]],
                                 modal = True)

        # We need to call read() at least once on the window to get it to
        # show up. "timeout = 0" means that the call will return immediately
        # (rather than waiting for the window to generate an event in
        # response to user interaction - which isn't likely to come, since we
        # don't have any clickable elments in it), allowing us to continue
        # and actually run the benchmarks. The window will then stay open
        # until we close it.
        #
        # Since we won't call read() again until we close the window, the
        # window will remain "grayed out" and not respond to user interaction
        # (including the "Close" button) - which is the desired behavior
        # here, since we don't have a way to interrupt the benchmark process
        # until it's done.
        event, values = popup_window.read(timeout = 0)

        bench_results = crypto_backend.benchmark()
        popup_window.close()

        sg.popup_scrolled(bench_results, size=(75, 10),
                          title = "Benchmark Results",
                          font = (MONOSPACE_FONT, 10))


window.close()
