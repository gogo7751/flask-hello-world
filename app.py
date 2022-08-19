from flask import Flask, jsonify
import os
from Crypto.Cipher import AES
import base64


class Aes_ECB(object):
    def __init__(self, key):
        self.key = key
        self.MODE = AES.MODE_ECB
        self.BS = AES.block_size
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(
            self.BS - len(s) % self.BS
        )
        self.unpad = lambda s: s[0 : -ord(s[-1])]

    def add_to_16(value):
        while len(value) % 16 != 0:
            value += "\0"
        return str.encode(value)

    def AES_encrypt(self, text):
        aes = AES.new(Aes_ECB.add_to_16(self.key), self.MODE)
        encrypted_text = str(
            base64.encodebytes(aes.encrypt(Aes_ECB.add_to_16(self.pad(text)))),
            encoding="utf-8",
        ).replace("\n", "")
        return encrypted_text

    def AES_decrypt(self, text):
        cipher = AES.new(Aes_ECB.add_to_16(self.key), self.MODE)
        decrypt_data = base64.b64decode(text)
        plain_text = cipher.decrypt(decrypt_data)
        return plain_text.decode("utf8").rstrip()


app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False


@app.route("/<string:_input>")
def hello_world(_input):
    key = os.environ.get("AES_KEY")
    aes = Aes_ECB(key)
    test_encrypt = aes.AES_encrypt(_input)
    test_decrypt = aes.AES_decrypt(test_encrypt)
    return (
        jsonify(
            {
                "input": _input,
                "test_encrypt": test_encrypt,
                "test_decrypt": test_decrypt,
            }
        ),
        200,
    )


if __name__ == "__main__":
    app.run(debug="True", host="0.0.0.0", port=5050)
