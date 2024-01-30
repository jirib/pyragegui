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

def load_recipients(files):
    """
    wrapper

    Parameters:

        files (str): Paths separated with semicolon
    
    Returns:

        recipients (str): Text with comments (max one) and recipients
    """

    text = [] # lines of text

    for file in files.split(";"):
        try:
            with open(file, "r") as f:
                text.extend(f.readlines())
        except Exception:
            # TODO: logging
            pass
    
    recipients = get_recipients("\n".join(text))
    return recipients


def get_recipients(lines):
    """
    Finds recipients public keys and if a comment exists right above the key,
    it is used (a hard guess).

        Parameters:

            lines (str): Text to search for recipients/comments

        Returns:

            recipients (str): Text with comments (optional) and recipients'
                              public keys
    """

    recipients = ""
    comments = []

    prefixes = ["#", "age1"] # lines to consider
    for line in [x.strip() for x in lines.splitlines() \
                 if x.startswith(tuple(prefixes))]:
        if line.startswith("#"):
            comments.append(line)
            continue
        elif line.startswith("age1"):
            try:
                pubkey = str(pyrage.x25519.Recipient.from_str(line))
                # hard guess, only the comment right above the public key!
                if comments:
                    recipients = "{}{}{}".format(
                        f"{recipients}\n" if recipients else "",
                        f"{comments[-1]}\n" if comments else "",
                        f"{pubkey}"
                    )
            except RecipientError: # line starting with 'age1' is not a pubkey
                continue
            finally:
                comments = [] # clear
        else:
            continue # ignore everything else

    return recipients
