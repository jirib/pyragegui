#!/usr/bin/env python3

import PySimpleGUI as sg
import pyrage
from datetime import datetime

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

# TODO:
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
        sg.Text(
            size=(600,5),
            key="-E-R-RECIPIENT-",
            background_color='grey',
            text_color='black',
            font=('Liberation Mono', 10))
    ],
    [
        sg.Text("Load an existing file with recipients"),
        sg.Push(),
        sg.Button("Load", key="-E-R-BROWSE-")
    ]
]

# what to encrypt
encr_actions = [
    [
        sg.Text("Select an existing file for encryption")
    ],
    [
        sg.Input(size=(70,0), key="-E-A-INPUTFILE-"),
        sg.Push(),
        sg.Button("Browse", key="-E-A-BROWSE-", size=(10,0))
    ],
    [
        sg.Push(),
        sg.Button("Encrypt", key="-E-A-ENCRYPT-"),
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
        sg.Text(
            size=(600,5),
            key="-D-I-KEY-",
            background_color='grey',
            text_color='black',
            font=('Liberation Mono', 10))
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
                    sg.Tab('Encrypt', encr_tab),
                    sg.Tab('Decrypt', decr_tab),
                    sg.Tab('Identity', identity_tab)
                ]
            ]
        )
    ]
]


# TODO: add bytes detection for age files
# load key file

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


def validate_recipient(recipient_str):
    print(recipient_str)
    try:
        recipient = [
            pyrage.x25519.Recipient.from_str(x) for x in recipient_str.splitlines() \
            if x.strip().startswith('age')
        ]
        if not recipient:
            raise Exception()
        return recipient
    except Exception as e:
        sg.popup_cancel(f"No valid recipient found!", title=None)
        return None


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


def encrypt_recipient(recipient=[], input_file=''):
    try:
        with open(input_file, 'r+b') as f:
            encrypted = pyrage.encrypt(f.read(), recipient)

        output_file = sg.popup_get_file('', save_as=True, no_window=True)
        with open(output_file, 'w+b') as f:
            f.write(encrypted)
    except Exception as e:
        sg.popup_cancel(f"Error!\n\n{e}", title=None)


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
    window = sg.Window("pyragegui", layout, margins=(2, 2), finalize=True)

    while True:
        event, values = window.read()
        print("Event: ", event, "    Values: ", values)

        if event in {sg.WIN_CLOSED, "Exit"}:
            break

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

        if event == "-E-R-BROWSE-":
            _f = sg.popup_get_file('', no_window=True)

            if _f:
                with open(_f, 'r') as f:
                    # WARNING: no validation yet
                    recipient = f.read()

                # TODO: allow loading multiple files one by one ??
                window["-E-R-RECIPIENT-"].update(value=recipient)
                del(_f)
            else:
                continue

        if event == "-E-A-BROWSE-":
            _f = sg.popup_get_file('', no_window=True)

            if _f:
                encr_file = _f
                window["-E-A-INPUTFILE-"].update(value=encr_file)
            else:
                continue

        if event == "-E-A-ENCRYPT-":

            # TODO: allow manual input
            if recipient and encr_file:
                recipient = validate_recipient(recipient)

                if not recipient:
                    continue

                encrypt_recipient(recipient=recipient, input_file=encr_file)

            else:
                # popup warning???
                pass

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
