from datetime import datetime
import pyrage
import re

def generate_key(comment=""):
    """
    Generates a x25519 key.

    Params:

        comment (str): A comment if available

    Returns:
        key_dict (string): A dict with 'keydata', 'comment-pubkey'
    """

    key_dict = {}

    key = str(pyrage.x25519.Identity.generate())
    pubkey = str(pyrage.x25519.Identity.from_str(key).to_public())

    key_dict["comment-pubkey"] = \
        f"# {comment}\n{pubkey}" if comment else pubkey

    key_dict["keydata"] = "{}# public key: {}\n{}".format(
        f"# {comment}\n" if comment else "",
        pubkey,
        key
    )

    return key_dict


def load_keys(keydata, all=False):
    """
    Loads keys from data.

    Params:

        keydata (string): Data for the key.

    Returns:

        keys (list): A list of dicts with 'keydata', 'comment'
    """

    keys = []
    i = 0 # multiple private keys might be present

    commented = []
    for line in keydata.splitlines():
        if line.startswith("#"):
            commented.append(line)
            continue
        elif line.startswith("AGE-SECRET-KEY-"):

            try: # test if key is valid
                key = str(pyrage.x25519.Identity.from_str(line))
                pubkey = str(pyrage.x25519.Identity.from_str(line).to_public())

                """
                An example of possible file with a secret key:

                # foobar@example.com
                # created: 2024-01-27T14:25:49+01:00
                # public key: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
                AGE-SECRET-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
                """

                key_data = [x for x in commented \
                    if (
                        x.startswith("# created: ") or
                        x.startswith("# public key:")
                    )
                ]
                key_data.append(key)

                # compare commented + key with key_data
                s = set(key_data)
                comments = [x for x in (commented + [line]) if x not in s]
                comment = comments[0] if comments else "" # hard guess, sorry
                keys.insert(
                    i, {
                        "keydata": "\n".join(
                            [comment] + key_data
                        ),
                        "comment": comment
                        }
                )
            except IdentityError:
                pass
            finally:
                i = i + 1
                commented = ""

    return keys


def update_comment_pubkey(comment, keydata):
    """
    Updates -COMMENT-PUBKEY- when one types any comment in -COMMENT-
    or when -LOAD-KEY is triggered

    Params:

        comment (str): Comment
        keydata (str): keydata

    Returns:
        text (str): Updated text for -COMMENT-PUBKEY-
    """

    key = pyrage.x25519.Identity.from_str(
        [x for x in keydata.splitlines() if x.startswith("AGE-SECRET-KEY-")][0]
    )

    pubkey = str(
        pyrage.x25519.Identity.to_public(key))

    # TODO: check lstrip() here
    text= f"# {comment.lstrip('# ')}\n{pubkey}" if comment else pubkey
    return text


def update_keydata(comment, keydata):
    """
    Updates -KEYDATA- when there is the -COMMENT- event

    Params:

        comment (str): Comment
        keydata (str): Existing key file

    Return:

        updated (str): Updated key data with new comment
    """

    """
    An existing private key file content may be (the first line -
    the comment) may or not be present:

    # foobar@example.com
    # created: 2024-01-27T14:25:49+01:00
    # public key: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    AGE-SECRET-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    """

    # keep only these lines, sorry, ignoring all others!
    keydata = [re.sub(r"^#\s*", "", x) for x in keydata.splitlines() \
        if (
            x.startswith("# created: ") or
            x.startswith("# public key:") or
            x.startswith("AGE-SECRET-KEY-")
        )
    ]

    comment = f"# {comment}\n" if comment else ""
    updated = "{}{}".format(
        comment,
        "\n".join(keydata)
    )

    return updated


def save_pubkey(comment_pubkey, filename):
    """
    Saves a public key, optionally with a defined comment.

    Params:
        comment_pubkey (str): Comment and public key
        pubkey (str): A string of a public key

    Returns:
        e (string): Exception
    """

    e = ""

    try:
        with open(filename, "wt", encoding="utf-8") as f:
            f.write(f"{comment_pubkey}\n")
    except Exception as e:
        return e


def save_private(keydata, filename, passphrase=""):
    """
    Saves a private key, if 'created' not found, add such a line

    Params:

        keydata (str): Per private key data
        filename (str): Path of the final output file
        passphrase (str): Optional passphrase

    Returns:

        e (string): Exception
    """

    """
    'keydata' may be:

    # foobar@example.com
    # created: 2024-01-27T14:25:49+01:00
    # public key: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    AGE-SECRET-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    """

    comments = []
    created = None

    lines = [x for x in keydata.splitlines()]
    for line in lines:
        if line.startswith("# created: "):
            created = line
        elif line.startswith("# public key: "):
            pubkey = line
        elif line.startswith("AGE-SECRET-KEY-"):
            key = line
        else:
            comments.append(line)

    comment = comments[0] if comments else "" # only one line comment!

    # created line is already present only if an existing private key was loaded,
    # thus if not present, let's add this line
    if not created:
        created = "# created: {}".format(
            datetime.now().astimezone().replace(microsecond=0).isoformat()
        )

    out = "{}{}\n{}\n{}\n".format(
        f"# {comment}\n" if comment else "",
        created,
        pubkey,
        key
    )
    e = ""

    if passphrase:
        out = pyrage.passphrase.encrypt(bytes(out, encoding="utf-8"), passphrase)

    try:
        with open(filename, "wb" if passphrase else "wt") as f:
            f.write(out)
    except Exception as e:
        return e
