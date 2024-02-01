import pytest
import pyrage

# key.py tests
from key import *


def test_generate_key():
    key_str = generate_key2()

    assert len(key_str.splitlines()) == 2 # two lines (pubkey, key)

    assert f"# public key: age1" in key_str.splitlines()[-2] # penultimate line
    assert f"AGE-SECRET-KEY-" in key_str.splitlines()[-1]    # last line

    private_str = key_str.splitlines()[-1]
    key = pyrage.x25519.Identity.from_str(private_str)
    assert type(key) == pyrage.x25519.Identity

    public_str = key_str.splitlines()[-2].split(":")[1].strip()
    public = pyrage.x25519.Recipient.from_str(public_str)
    assert type(public) == pyrage.x25519.Recipient


def test_generate_key_with_comment():
    comment = "foo@example.com"
    key_str = generate_key2(comment)

    assert len(key_str.splitlines()) == 3 # three lines (comment, pubkey, key)
    assert f"# {comment}" in key_str.splitlines()[0] # on first line

    assert f"# public key: age1" in key_str.splitlines()[-2] # penultimate line
    assert f"AGE-SECRET-KEY-" in key_str.splitlines()[-1]    # last line

    private_str = key_str.splitlines()[-1]
    key = pyrage.x25519.Identity.from_str(private_str)
    assert type(key) == pyrage.x25519.Identity

    public_str = key_str.splitlines()[-2].split(":")[1].strip()
    public = pyrage.x25519.Recipient.from_str(public_str)
    assert type(public) == pyrage.x25519.Recipient


tmp_key = pyrage.x25519.Identity.generate()
tmp_key_str = str(tmp_key)
tmp_pubkey_str = str(tmp_key.to_public())
@pytest.mark.parametrize("keydata, expected_result", [
    (
        tmp_key_str,
        tmp_key_str,
    ),
    (
        "{blank_line}{private_key}".format(
            blank_line = f"     \n",
            private_key = tmp_key_str
        ),
        tmp_key_str,
    ),
    (
        "{blank_prefix}{private_key}".format(
            blank_prefix = f"    ",
            private_key = tmp_key_str
        ),
        tmp_key_str,
    ),
    (
        "{one_comment}{private_key}".format(
            one_comment = f"# foo@example.com\n",
            private_key = tmp_key_str
        ),
        "{one_comment}{private_key}".format(
            one_comment = f"# foo@example.com\n",
            private_key = tmp_key_str
        ),
    ),
    (
        "{blanks_comment}{private_key}".format(
            blanks_comment = f"    # foo@example.com\n",
            private_key = tmp_key_str
        ),
        "{blanks_comment}{private_key}".format(
            blanks_comment = f"    # foo@example.com\n",
            private_key = tmp_key_str
        ),
    ),
    (
        "AGE-SECRET-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", # bogus
        None
    ),
    (
        f"0xDEADBEEF",
        None
    ),
    (
        "{comment}{metadata}{private_key}".format(
            comment = "# foobar@example.com\n",
            metadata = f"# created: 2024-01-27T14:25:49+01:00\n# public key: {tmp_pubkey_str}\n",
            private_key = tmp_key_str
        ),
        "{comment}{metadata}{private_key}".format(
            comment = "# foobar@example.com\n",
            metadata = f"# created: 2024-01-27T14:25:49+01:00\n# public key: {tmp_pubkey_str}\n",
            private_key = tmp_key_str
        )
    ),
    (
        "{bogus_comments}{good_comment}{private_key}".format(
            bogus_comments = f"# nonsense\n# other nonsense\n",
            good_comment = "# foobar@example.com\n",
            private_key = tmp_key_str
        ),
        "{good_comment}{private_key}".format(
            good_comment = "# foobar@example.com\n",
            private_key = tmp_key_str
        )
    )
])


def test_load_key_valid(keydata, expected_result):
    result = load_keys2(keydata)
    assert result == expected_result


if __name__ == "__main__":
    pytest.main()
