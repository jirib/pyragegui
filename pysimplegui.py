import PySimpleGUI as sg
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
from key import *
from encrypt import *
from decrypt import *

recipients_rmenu = ["", ["Paste recipients"]]
identities_rmenu = ["", ["Paste identities"]]

identity_key = [
    [
        sg.Text("", key="-PUBKEY-NOTE-", visible=False)
    ],
    [
        sg.Text(
            "No key",
            key="-COMMENT-PUBKEY-",
            size=(600,5),
            background_color='grey',
            text_color='black',
            font=('Liberation Mono', 10),
            enable_events=True)
    ],
    [
        sg.Input(key="-KEYDATA-", visible=False),
    ],
    [
        sg.Input(key="-PUBKEY-", visible=False),
    ],
    [
        sg.Text("Key comment:", size=(15,0)),
        sg.InputText(size=(600, 1), key="-COMMENT-", enable_events=True)
    ],
    [
        sg.Text("Key passphrase:", size=(15,0)),
        sg.InputText(size=(600, 0), key="-PASSPHRASE-KEY-", password_char="*")
    ],
    [
        sg.Text("Confirm:", size=(15,0)),
        sg.InputText(size=(600, 0), key="-CONFIRM-KEY-", password_char="*", enable_events=True)
    ]
]

identity_actions = [
    [
        sg.Text("Generate a public/private X25519 key pair", size=(40,0)),
        sg.Push(),
        sg.Button("Generate", key="-GENERATE-")
    ],
    [
        sg.Text("Load an existing private X25519 key file", size=(40,0)),
        sg.Push(),
        sg.Input(visible=False, enable_events=True, key="-LOAD-KEY-"),
        sg.FileBrowse("Load")
    ],
    [
        sg.Text("Save the generated key", size=(40,0)),
        sg.Push(),
        sg.Button("Save public key", key="-SAVE-PUBKEY-"),
        sg.Button("Save private key", key="-SAVE-KEY-")
    ]
]

identity_tab = [
    [
        sg.Frame('Identity', layout=identity_key, size=(600, 220))
    ],
    [
        sg.Frame('Actions', layout=identity_actions, size=(600, 160))
    ]
]

# TODO: add passphrase feature
encr_mode = [
    [
        sg.Push(),
        sg.Radio("Passphrase", "ENCR_MODE", default=False, key="-ENCRYPT-PASSPHRASE-", enable_events=True),
        sg.Radio("Recipient", "ENCR_MODE", default=True, key="-ENCRYPT-RECIPIENT-", enable_events=True),
        sg.Push()
    ]
]

# for whom to encrypt
recipient_text = """Write manually, paste from clipboard or load recipients from an exixting file.
Only commented out, empty lines and ones with valid recipients are accepted."""

encr_recipient = [
    [
        sg.Multiline(
            size=(600,5),
            key="-RECIPIENTS-",
            background_color='grey',
            text_color='black',
            font=('Liberation Mono', 10),
            right_click_menu=recipients_rmenu,
            tooltip=recipient_text)
    ],
    [
        sg.Text("Add recipients from one or more existing files"),
        sg.Push(),
        sg.Input(visible=False, enable_events=True, key="-RECIPIENTS-LOAD-"),
        sg.FilesBrowse("Load")
    ]
]

encr_passphrase = [
    [
        sg.Text("Passphrase:", size=(15, 0)),
        sg.InputText(size=(600, 0), password_char="*", key="-PASSPHRASE-ENCRYPT-")
    ],
    [
        sg.Text("Confirm:", size=(15, 0)),
        sg.InputText(size=(600, 0), password_char="*", key="-CONFIRM-ENCRYPT-", enable_events=True)
    ]
]
# what to encrypt
encr_actions = [
    [
        sg.Text("Select an existing file for encryption")
    ],
    [
        sg.Input(size=(70,0), enable_events=True, key="-IN-PLAINFILE-"),
        sg.Push(),
        sg.FileBrowse("Select", target=("-IN-PLAINFILE-"))
    ],
    [
        sg.Push(),
        sg.Button("Encrypt", key="-ENCRYPT-"),
        sg.Push()
    ]
]

encr_tab = [
    [
        sg.Frame('Modes', layout=encr_mode, size=(600,45))
    ],
    [
        sg.Frame('Recipient', layout=encr_recipient, key="-RECIPIENT-", size=(600,170)),
        sg.Frame("Passphrase", layout=encr_passphrase, key="-PASSPHRASE-", size=(600, 170), visible=False)
    ],
    [
        sg.Frame("Actions", layout=encr_actions, size=(600,120))
    ]
]


# decrypt tab
decr_mode = [
    [
        sg.Push(),
        sg.Radio("Passphrase", "DECR_MODE", default=False, key="-DECRYPT-PASSPHRASE-", enable_events=True),
        sg.Radio("Identity", "DECR_MODE", default=True, key="-DECRYPT-IDENTITY-", enable_events=True),
        sg.Push()
    ],

]

# with whom to decrypt
decr_identity = [
    [
        sg.Text('INFO: For privacy reasons, the private key is not fully shown')
    ],
    [
        sg.Multiline(
            size=(600,5),
            key="-IDENTITIES-",
            background_color='grey',
            text_color='black',
            font=('Liberation Mono', 10),
            right_click_menu=identities_rmenu)
    ],
    [
        sg.Text("Load an existing file with key", size=(40,0)),
        sg.Push(),
        sg.Button("Browse", key="-D-I-BROWSE-")
    ]
]

decr_passphrase = [
    [
        sg.Text("Passphrase:", size=(15, 0)),
        sg.InputText(size=(600, 0), password_char="*", key="-PASSPHRASE-DECRYPT-")
    ]
]
# what to decrypt
decr_actions = [
    [
        sg.Text("Select an existing file for decryption")
    ],
    [
        sg.Input(size=(70,0), key="-D-A-INPUTFILE-"),
        sg.Push(),
        sg.Button("Browse", key="-D-A-BROWSE-", size=(10,0))
    ],
    [
        sg.Push(),
        sg.Button("Decrypt", key="-D-A-DECRYPT-"),
        sg.Push()
    ]
]

decr_tab = [
    [
        sg.Frame('Modes', layout=decr_mode, size=(600, 45))
    ],
    [
        sg.Frame("Identity", layout=decr_identity, key="-DECRYPT-IDENTITY-INPUT-", size=(600, 170)),
        sg.Frame("Passphrase", layout=decr_passphrase, key="-DECRYPT-PASSPHRASE-INPUT-", size=(600, 170), visible=False)

    ],
    [
        sg.Frame('Actions', layout=decr_actions, size=(600, 120))
    ]
]

layout = [
    [
        sg.TabGroup(
            [
                [
                    sg.Tab('Identity', identity_tab),
                    sg.Tab('Encrypt', encr_tab, key='encr_tab'),
                    sg.Tab('Decrypt', decr_tab)
                ]
            ]
        )
    ]
]


def main():
    location = sg.Window.get_screen_size()
    window = sg.Window("pyragegui", layout, margins=(2, 2), finalize=True, location=location)
    window['encr_tab'].select()
    window.refresh()
    window.move_to_center()

    # # test
    # multiline = window['-RECIPIENTS-']
    # widget = multiline.Widget
    # widget.tag_config('COMMENT', foreground='grey')
    print("XXX")

    while True:
        event, values = window.read()
        print("Event: ", event, "    Values: ", values)

        if event in {sg.WIN_CLOSED, "Exit"}:
            break

        # passphrase/confirm match background coloring
        if event.startswith("-CONFIRM"):
            type = event.split("-")[2] # -CONFIRM-KEY- -> KEY
            if values[f"-CONFIRM-{type}-"] != values[f"-PASSPHRASE-{type}-"]:
                window[f"-CONFIRM-{type}-"].update(background_color="yellow")
            else:
                window[f"-CONFIRM-{type}-"].update(background_color="white")

        #################################################
        ################## IDENTITY #####################
        #################################################

        if event == "-COMMENT-" and window["-KEYDATA-"].get(): # key data loaded?

            text = update_comment_pubkey(
                values["-COMMENT-"], window["-KEYDATA-"].get()
            )
            window["-COMMENT-PUBKEY-"].update(text)

            # update "private" part too
            text = update_keydata(
                values["-COMMENT-"],
                window["-KEYDATA-"].get()
            )
            window["-KEYDATA-"].update(text)


        if event == "-GENERATE-":
            comment = values["-COMMENT-"] \
                if ("-COMMENT-" in values and values["-COMMENT-"]) else ""
            # keydata comment-pubkey
            key = generate_key(comment)
            for k, v in key.items():
                window[f"-{k.upper()}-"].update(v)
                window["-PUBKEY-NOTE-"].update("Public key to share with other users:")
                window["-PUBKEY-NOTE-"].update(visible=True)


        if event == "-LOAD-KEY-":
            with open(values["-LOAD-KEY-"], "r+b") as f: # load as bytes for encrypted key files
                keydata = f.read()
                type = detect_age(keydata)

            if not type == "plain": # encrypted key found!
                askpass = sg.popup_get_text("Enter passphrase: ", password_char="*")
                while True:
                    decrypted = decr_passphrase(keydata, askpass)
                    if decrypted:
                        keydata = decrypted
                        continue

            keydata = bytes.decode(keydata, encoding="utf-8") # convert to string now

            key = load_keys(keydata)[0] # load only first key here!

            window["-KEYDATA-"].update(key["keydata"])
            window["-COMMENT-PUBKEY-"].update(
                update_comment_pubkey(
                    key["comment"],
                    key["keydata"]
                )
            )
            window["-PUBKEY-NOTE-"].update("Public key to share with other users:")
            window["-PUBKEY-NOTE-"].update(visible=True)


        if event in ["-SAVE-PUBKEY-", "-SAVE-KEY-"]:
            comment = f"{window['-COMMENT-'].get()}" \
                         if window["-COMMENT-"].get() else "" # always save comment

            if event == "-SAVE-PUBKEY-":

                if window["-COMMENT-PUBKEY-"].get():
                    filename = sg.popup_get_file('', save_as=True, no_window=True)
                    if filename:
                        err = save_pubkey(
                            window["-COMMENT-PUBKEY-"].get(),
                            filename,
                        )
                        if err:
                            sg.popup_error(err, title="")
                        else:
                            sg.popup("Public key was saved.")

            if event == "-SAVE-KEY-":
                if window["-KEYDATA-"].get():
                    filename = sg.popup_get_file("", save_as=True, no_window=True)
                    if not filename:
                        continue

                    # passphrase / confirm match check
                    if window["-PASSPHRASE-KEY-"].get() != window["-CONFIRM-KEY-"].get():
                        sg.popup_error("Passphrase does not match!")
                        continue

                    err = save_private(
                        window["-KEYDATA-"].get(),
                        filename,
                        f"{window['-PASSPHRASE-KEY-'].get()}" \
                                if window["-PASSPHRASE-KEY-"] else ""
                    )

                    if err:
                        sg.popup_error(err, title="")
                    else:
                        sg.popup("Private key was saved.")


        #################################################
        ################# ENCRYPTION ####################
        #################################################

        # TODO: localize right click menu text
        if event == "Paste recipients":
            text = window["-RECIPIENTS-"]
            clipboard = sg.clipboard_get()
            recipients = get_recipients(clipboard)
            if recipients:
                text.update(
                    f"{text.get()}\n{recipients}" if text.get() else recipients
                )
                found_int = len(
                    [x for x in recipients.splitlines() if x.startswith("age1")]
                )
                sg.popup(f"{found_int} recipients pasted.", title="")

            else:
                sg.popup_error("No recipient found!")


        if event == "-RECIPIENTS-LOAD-":
            recipients = load_recipients(values["-RECIPIENTS-LOAD-"])
            if not recipients:
                sg.popup_error("No recipients' public keys found!")
                continue
            else:
                text = window["-RECIPIENTS-"]
                text.update(
                    "{}\n{}".format(text.get(), recipients) if text.get() else recipients
                )
                found_int = len(
                    [x for x in recipients.splitlines() if x.startswith("age1")]
                )
                sg.popup(
                    f"{found_int} recipients found.", title="")


        encr_modes = ["-ENCRYPT-PASSPHRASE-", "-ENCRYPT-RECIPIENT-"]
        if event in encr_modes:
            deactivate = encr_modes[0] if encr_modes[0] != event \
                else encr_modes[1]
            window[event.removeprefix("-ENCRYPT")].update(visible=True)
            window[deactivate.removeprefix("-ENCRYPT")].update(visible=False)


        if event == "-ENCRYPT-":

            if not values["-IN-PLAINFILE-"]:
                sg.popup_error("No files to encrypt are defined!")
                continue

            if values["-ENCR-RECIPIENT-"]:
                good_recipient = valid_recipient(values["-RECIPIENTS-"])

                if not good_recipient:
                    sg.popup_error("No recipient found!")
                    continue

                encrypted = encrypt_recipient(good_recipient, values["-IN-PLAINFILE-"])
                outfile = sg.popup_get_file("", save_as=True, no_window=True)
                try:
                    with open(outfile, "w+b") as f:
                        f.write(encrypted)
                    sg.popup("Encryption done.")
                except:
                    sg.popup_error("Error to save the file!")

            elif values["-ENCR-PASSPHRASE-"]:

                # passphrase / confirm match check
                if window["-PASSPHRASE-ENCRYPT-"].get() != window["-CONFIRM-ENCRYPT-"].get():
                    sg.popup_error("Passphrase does not match!")
                    continue

                encrypted = encrypt_passphrase(
                    window["-PASSPHRASE-ENCRYPT-"].get(),
                    values["-IN-PLAINFILE-"]
                )
                outfile = sg.popup_get_file("", save_as=True, no_window=True)
                if outfile:
                    try:
                        with open(outfile, "w+b") as f:
                            f.write(encrypted)
                        sg.popup("Encryption done.")
                    except:
                        sg.popup_error("Error to save the file!")



        #################################################
        ################# DECRYPTION ####################
        #################################################

        decr_modes = ["-DECRYPT-PASSPHRASE-", "-DECRYPT-IDENTITY-"]
        if event in decr_modes:
            deactivate = decr_modes[0] if decr_modes[0] != event \
                else decr_modes[1]
            window[f"{event}INPUT-"].update(visible=True)
            window[f"{deactivate}INPUT-"].update(visible=False)

        ##### identity #####
        if event == "-D-I-BROWSE-":
            _f = sg.popup_get_file('', no_window=True)

            if _f:
                decr_ident, _ = load_key(_f)
                del(_f)

                if not decr_ident:
                    continue

                window["-D-I-KEY-"].update(value=obfuscale_key(decr_ident))

            else:
                continue

        ##### actions #####
        if event == "-D-A-BROWSE-":
            _f = sg.popup_get_file('', no_window=True)

            if _f:
                decr_file = _f
                del(_f)
                window["-D-A-INPUTFILE-"].update(value=decr_file)
            else:
                continue

        if event == "-D-A-DECRYPT-":
            print(decr_ident, decr_file)
            if decr_ident and decr_file:
                # TODO: support more identities
                decrypt_identity(
                    identity=[decr_ident], input_file=decr_file
                )


    window.close()

# main
if __name__ == "__main__":
    main()
