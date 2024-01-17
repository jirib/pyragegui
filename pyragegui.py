#!/usr/bin/env python3

import PySimpleGUI as sg
import pyrage
from datetime import datetime

recipients_rmenu = ["", ["Paste recipients"]]
identities_rmenu = ["", ["Paste identities"]]


identity_key = [
    [
        sg.Text("", key="-I-K-HEADING-")
    ],
    [
        sg.Text(
            "No key",
            key="-I-K-PUBKEY-",
            size=(600,5),
            background_color='grey',
            text_color='black',
            font=('Liberation Mono', 10))
    ],
    [
        sg.Text("Key comment:", size=(15,0)),
        sg.InputText(size=(600, 0), key="-I-K-COMMENT-")
    ],
    [
        sg.Text("Key passphrase:", size=(15,0)),
        sg.InputText(size=(600, 0), key="-I-K-PASSPHRASE-", password_char="*")
    ],
    [
        sg.Text("Confirm:", size=(15,0)),
        sg.InputText(size=(600, 0), key="-I-K-CONFIRM-", password_char="*")
    ]
]

identity_actions = [
    [
        sg.Text("Generate a public/private X25519 key pair", size=(40,0)),
        sg.Push(),
        sg.Button("Generate", key="-I-A-GENERATE-")
    ],
    [
        sg.Text("Load an existing private X25519 key file", size=(40,0)),
        sg.Push(),
        sg.Button("Load", key="-I-A-LOAD-")
    ],
    [
        sg.Text("Save the generated key", size=(40,0)),
        sg.Push(),
        sg.Button("Save public key", key="-I-A-SAVEPUB-"),
        sg.Button("Save private key", key="-I-A-SAVEPRIVATE-")
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
        sg.Radio("Passphrase", "ENCR_MODE", default=False, key="-ENCR_PASSPHRASE-"),
        sg.Radio("Recipient", "ENCR_MODE", default=True, key="-ENCR_RECIPIENT-"),
        sg.Push()
    ]
]

# for whom to encrypt
encr_recipient = [
    [
        sg.Multiline(
            size=(600,5),
            key="-RECIPIENTS-",
            background_color='grey',
            text_color='black',
            font=('Liberation Mono', 10),
            right_click_menu=recipients_rmenu)
    ],
    [
        sg.Text("Add recipients from one or more existing files"),
        sg.Push(),
        sg.Input(visible=False, enable_events=True, key="-IN-RECIPIENTS-"),
        sg.FilesBrowse("Load")
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
        sg.Button("Encrypt"),
        sg.Push()
    ]
]

encr_tab = [
    [
        sg.Frame('Modes', layout=encr_mode, size=(600,45))
    ],
    [
        sg.Frame('Recipient', layout=encr_recipient, size=(600,170))
    ],
    [
        sg.Frame("Actions", layout=encr_actions, size=(600,120))
    ]
]


# decrypt tab
decr_mode = [
    [
        sg.Push(),
        sg.Radio("Passphrase", "DECR_MODE", default=False, key="-DECR_PASSPHRASE-"),
        sg.Radio("Key", "DECR_MODE", default=True, key="-DECR_KEY-"),
        sg.Push()
    ]
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
        sg.Frame('Identity', layout=decr_identity, size=(600, 170))
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


def load_recipient(files):
    """
    Returns a string if a recipient is found.

        Parameters:
            files (str): Files separated with semicolon

        Returns:
            recipient (str): String of a file with recipients
    """

    _out = [] # helper var

    for filename in files.split(";"):
        with open(filename, "r") as f:
            lines = f.readlines()
            if any([line for line in lines if line.startswith('age1')]):
                _out.extend([line.strip() for line in lines])

    recipient = "\n".join(_out) if _out else ""
    return recipient


def load_key(filename):
    with open(filename, 'r') as f:
        try:
            input = f.readlines()
            # WARNING: only first key found will be used!
            key_str = [x.strip() for x in input if x.startswith("AGE-SECRET-KEY-")][0]
            try:
                ident = pyrage.x25519.Identity.from_str(key_str)
                pubkey = str(ident.to_public())
                comments = "\n".join([
                    x.strip() for x in input \
                    if not (x.strip().startswith("AGE-SECRET-KEY-") or x.strip().endswith(pubkey))
                ])
                return ident, "{}{}".format(
                    f"{comments}\n" if comments else f"",
                    pubkey
                )
            except IdentityError:
                return None
        except UnicodeDecodeError:
                pass

    with open(filename, 'r+b') as b:
        def ask_pass():
            ret = sg.popup_get_text("Enter passphrase: ",
                password_char = "*"
            )
            return ret

        try:
            out = pyrage.passphrase.decrypt(
                b.read(),
                ask_pass()
            )
            input = out.decode('utf-8').splitlines()

            # WARNING: only first key found will be used!
            ident = pyrage.x25519.Identity.from_str(
                [
                    x.strip() for x in out.decode('utf-8').splitlines() \
                    if x.strip().startswith('AGE-SECRET-KEY-')][0]
            )
            pubkey = str(ident.to_public())
            comments = "\n".join([
                x.strip() for x in input \
                if not (x.strip().startswith('AGE-SECRET-KEY-') or x.strip().endswith(pubkey))
            ])
            return ident, "{}{}".format(
                f"{comments}\n" if comments else f"",
                pubkey
            )
        except pyrage.DecryptError as e:
            sg.popup_cancel(f"Could not decrypt the key!\n\n{e}", title=None)
            return None, None



def save_private(ident=None, comment='', passphrase='', outfile=''):
    created = datetime.now().astimezone().replace(microsecond=0).isoformat()
    comment = f"# {comment}\n" if comment else ""

    out = "{}# created: {}\n# public key: {}\n{}\n".format(
        comment,
        created,
        str(ident.to_public()),
        str(ident)
    )

    if passphrase:
        out = pyrage.passphrase.encrypt(bytes(out, encoding="ascii"), passphrase)
        mode="wb"
        with open(outfile, "wb") as f:
            f.write(out)
    else:
        with open(outfile, "wt", encoding="utf-8") as f:
            f.write(out)


def save_pubkey(pubkey='', comment='', outfile=''):
    comment = f"# {comment}\n" if comment else ""

    out = "{}{}\n".format(
        comment,
        pubkey
    )

    with open(outfile, "wt", encoding="utf-8") as f:
        f.write(out)


def valid_recipient(recipient):
    """
    Returns a list of recipients.

        Parameters:
            recipient (str): A string to check if there is a recipient

        Returns:
            ret (list): List with valid only recipients (Recipient object)
    """

    ret = list()

    lines = list(l for l in recipient.splitlines() if l.startswith('age1'))
    if lines:
        for line in lines:
            try:
                ret.append(
                    pyrage.x25519.Recipient.from_str(line.strip())
                )
            except pyrage.RecipientError:
                pass
    return ret


def validate_identity(identity_str):
    try:
        identity = [
            pyrage.x25519.Identity.from_str(x) \
            for x in identity_str.splitlines() \
            if x.strip().startswith('AGE-SECRET-KEY-')
        ]
        if not identity:
            raise Exception()
        return identity
    except Exception as e:
        sg.popup_cancel(f"No valid identity found!", title=None)
        return None


def encrypt_recipient(recipient, filename):
    """
    Encrypts a file to one or more recipients.

    Params:
        recipient (list): List of valid recipients Recipient objects

    Returns:
        encrypted (bytes): Encrypted bytes
    """


    with open(filename, 'r+b') as f:
        encrypted = pyrage.encrypt(f.read(), recipient)
    return encrypted


def decrypt_identity(identity=[], input_file=''):
    # TODO: issue here
    try:
        with open(input_file, 'r+b') as f:
            decrypted = pyrage.decrypt(f.read(), identity)

        output_file = sg.popup_get_file('', save_as=True, no_window=True)
        with open(output_file, 'w+b') as f:
            f.write(decrypted)
    except Exception as e:
        sg.popup_cancel(f"Error!\n\n{e}", title=None)


def obfuscale_key(ident):
    key_str = str(ident)
    prefix = 'AGE-SECRET-KEY-'
    start = key_str[len(prefix):len(prefix)+6]
    end = key_str[-6:]
    stars = "*" * (len(prefix)+len(start)+len(end))
    return f"{prefix}{start}{stars}{end}"


def identity_key_update(ident_pubkey):
    heading_str = "Public key for share with other users:"
    window["-I-K-HEADING-"].update(value=heading_str)
    window["-I-K-PUBKEY-"].update(value=ident_pubkey)


# main
if __name__ == "__main__":
    location = sg.Window.get_screen_size()
    window = sg.Window("pyragegui", layout, margins=(2, 2), finalize=True, location=location)
    window['encr_tab'].select()
    window.refresh()
    window.move_to_center()

    while True:
        event, values = window.read()
        print("Event: ", event, "    Values: ", values)

        if event in {sg.WIN_CLOSED, "Exit"}:
            break


        if event.startswith("Paste"):
            text = window["-RECIPIENTS-" if event.endswith("recipients") else "-IDENTITIES-"]
            text.update(
                "{}\n{}".format(text.get(), sg.clipboard_get()) if text.get() \
                else sg.clipboard_get()
            )


        #################################################
        ################## IDENTITY #####################
        #################################################

        ##### actions #####
        if event == "-I-A-GENERATE-":
            ident_ident = pyrage.x25519.Identity.generate()
            ident_pubkey = str(ident_ident.to_public())
            ident_pubkey = ident_pubkey if not values["-I-K-COMMENT-"] \
                else "# {}\n{}\n".format(values["-I-K-COMMENT-"], ident_pubkey)
            identity_key_update(ident_pubkey)


        if event == "-I-A-LOAD-":
            _f = sg.popup_get_file('', no_window=True)

            if _f:
                ident_file = _f
                ident_ident, ident_pubkey = load_key(ident_file)
                if not ident_ident:
                    continue
                window["-I-K-PUBKEY-"].update(value=ident_pubkey)
                del(_f)
            else:
                continue

        if event == "-I-A-SAVEPUB-":
            if ident_ident and ident_pubkey:
                _f = sg.popup_get_file('', save_as=True, no_window=True)

                if _f:
                    ident_pubfile = _f
                    del(_f)
                    save_pubkey(
                        pubkey_str=str(ident_ident.to_public()),
                        comment=values["-I-K-COMMENT-"],
                        outfile=ident_pubfile
                    )
                else:
                    continue

        if event == "-I-A-SAVEPRIVATE-":
            print('XXX', type(ident_ident))
            if ident_ident:
                _f = sg.popup_get_file('', save_as=True, no_window=True)

                if _f:
                    save_privatefile = _f
                    del(_f)
                    passphrase_lst = ["-I-K-PASSPHRASE-", "-I-K-CONFIRM-"]
                    if all(values[k] is not None for k in passphrase_lst) \
                       and (values[passphrase_lst[0]] == values[passphrase_lst[1]]):
                        passphrase=values["-I-K-PASSPHRASE-"]


                    save_private(
                        ident=ident_ident,
                        comment=values["-I-K-COMMENT-"],
                        passphrase=passphrase,
                        outfile=save_privatefile)


        #################################################
        ################# ENCRYPTION ####################
        #################################################

        if event == "-IN-RECIPIENTS-":
            recipient = load_recipient(values["-IN-RECIPIENTS-"])
            good_recipient = valid_recipient(recipient)
            if not good_recipient:
                sg.popup_error("No recipient found!")
                continue
            else:
                text = window["-RECIPIENTS-"]
                text.update(
                    "{}\n{}".format(text.get(), recipient) if text.get() else recipient
                )
                sg.popup(f"{len(good_recipient)} recipients found.", title="")


        if event == "Encrypt":
            # TODO: add passphrase functinality
            good_recipient = valid_recipient(values["-RECIPIENTS-"])

            if not good_recipient:
                sg.popup_error("No recipient found!")
                continue

            if not values["-IN-PLAINFILE-"]:
                sg.popup_error("No files to encrypt are defined!")
                continue

            encrypted = encrypt_recipient(good_recipient, values["-IN-PLAINFILE-"])
            outfile = sg.popup_get_file("", save_as=True, no_window=True)
            try:
                with open(outfile, "w+b") as f:
                    f.write(encrypted)
                sg.popup(f"""Encrypted copy of
                         {values["-IN-PLAINFILE-"]}
                         was save to
                         {outfile}""")
            except:
                sg.popup_error("Error to save the file!")


        #################################################
        ################# DECRYPTION ####################
        #################################################

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
