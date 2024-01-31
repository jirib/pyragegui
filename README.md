pyragegui
=========

<p align="center"><img alt="The age logo, an wireframe of St. Peters
dome in Rome, with the text: age, file encryption" width="600"
src="https://user-images.githubusercontent.com/1225294/132245842-fda4da6a-1cea-4738-a3da-2dc860861c98.png"></p>

This is a simple attempt for a GUI for the file encryption tool
[age](https://age-encryption.org), built on top of
[pyrage](https://github.com/woodruffw/pyrage) and currently
[PySimpleGUI](https://www.pysimplegui.org/en/latest/).

<p align="center"><img alt="pyragegui" width="630" src="https://raw.githubusercontent.com/jirib/pyragegui/main/pyragegui.png"></p>

TODO
----

### GUI framework

- [ ] QT (pyqt)

### Identity

- [x] generate key (if comment is field, show it with the generated public code)
- [x] load existing key (if code has a comment, show it with the generated public code)
- [x] "protect" the key with a passphrase
- [x] save public key (a comment - optional, public key)
- [x] save private key (a comment - optional, 'created', 'public key', the key itself

### Encrypt

- [x] encryption modes: passphrase x recipient
- [x] (passphrase) ask for the passphrase and confirm it
- [x] (recipient) populate multiline form with recipients from one or more files,
      if there is a comment above each public key, show it as well
- [x] show popup how many recipients were loaded from file(s)
- [x] (file) select a file for encryption
- [ ] (input) have a multiline form to enter an input text to encrypt
- [x] (outfile) encrypt to an output file
- [ ]  (armor) encrypt input to the armor format

### Decrypt

- [x] decryption modes: passphrase x recipient
- [ ] (passphrase) ask for the passphrase for the decryption
- [ ] (identity) populate multiline form with identities from one or more files,
      if there is a comment above each private key, show it as well;
      obfuscate the visible private key for security reasons
- [ ] show popup how many identities were loaded from file(s)
- [ ] (file) select a file for decryption
- [ ] (input) have a multiline form to enter armor format of encrypted text
- [ ] (outfile) save decrypted data to an output file
- [ ] (plain) show decrypted plain-text in multiline r/o form

### OS integration

- [ ] 'encrypt mode': allow the tool to be called with `-encrypt %f' and
      show only 'Encrypt' tab
- [ ] 'decrypt mode': allow the tool to be called with `-decrypt %f' and
      show only 'Decrypt' tab
- [ ] Windows explorer menu integration

### Localization

- [ ] Czech
- [ ] Italian
- [ ] French
- [ ] ...

### Tests

- [ ] pytest for python code
- [ ] GUI tests

### Packaging

- [ ] Linux portable 'package'
- [ ] Windows exe
- [ ] windows installer
- [ ] MacOS app
