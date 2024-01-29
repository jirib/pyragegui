import pyrage

def encrypt_passphrase(passphrase, filename):
    """
    Encrypts a file with a passphrase

    Params:
        passphrase (str): Secret passphrase
        filename (str): Path of a file to encrypt

    Returns:
        encrypted (bytes): Encrypted bytes
    """

    with open(filename, 'r+b') as f:
        encrypted = pyrage.passphrase.encrypt(f.read(), passphrase)
    return encrypted


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
