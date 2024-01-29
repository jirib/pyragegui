import pyrage

def detect_age(data):
    """
    Detects if input data are encrypted with age.

    Params:

        data (bytes): Input data

    Returns:

        type (str): Type of age file or None
    """

    type = None
    # TODO: add more detection
    try:
        if bytes.decode(
                data.splitlines()[-1],
                encoding="utf-8").startswith("AGE-SECRET-KEY-"):
            # plain text age key
            return "plain"
    except UnicodeDecodeError: # mimics magic crypt definitions
        if data.splitlines()[0] == b"age-encryption.org/v1": # encrypted file
            if data[25:31] == b"scrypt": # passphrase encrypted
                return "scrypt"


def decr_passphrase(ciphertext, passphrase):
    """
    Decrypts a encrypted text (bytes) and returns bytes.

    Params:

        ciphertext (bytes): Encrypted content
        passphrase (string): passphrase

    Returns:
        decrypted (bytes): Decrypted data

    """

    decrypted = pyrage.passphrase.decrypt(ciphertext, passphrase)
    return decrypted


# TODO: allow obfuscating multiple keys
def obfuscale_key(ident):
    key_str = str(ident)
    prefix = 'AGE-SECRET-KEY-'
    start = key_str[len(prefix):len(prefix)+6]
    end = key_str[-6:]
    stars = "*" * (len(prefix)+len(start)+len(end))
    return f"{prefix}{start}{stars}{end}"


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
