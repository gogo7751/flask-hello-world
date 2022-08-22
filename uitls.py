from Crypto.Cipher import AES
import base64
import os


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


import boto3
from botocore.exceptions import ClientError


class Ses(object):
    def __init__(self, recipeint, body_text):
        # The subject line for the email.
        self.SUBJECT = "驗證碼"
        # The email body for recipients with non-HTML email clients.
        self.BODY_TEXT = body_text
        # Replace sender@example.com with your "From" address.
        # This address must be verified with Amazon SES.
        self.SENDER = "CEX Verify <ericsychang@taiwanmobile.com>"
        # Replace recipient@example.com with a "To" address. If your account
        # is still in the sandbox, this address must be verified.
        self.RECIPIENT = recipeint
        # The character encoding for the email.
        self.CHARSET = "UTF-8"
        # Create a new SES resource and specify a region.
        self.CLIENT = boto3.client(
            "ses",
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            region_name="ap-northeast-1",
        )

    # set, comment the following variable, and the
    # ConfigurationSetName=CONFIGURATION_SET argument below.
    # CONFIGURATION_SET = "ConfigSet"

    def ses_send_email(self):
        # Try to send the email.
        try:
            # Provide the contents of the email.
            response = self.CLIENT.send_email(
                Destination={
                    "ToAddresses": [
                        self.RECIPIENT,
                    ],
                },
                Message={
                    "Body": {
                        "Text": {
                            "Charset": self.CHARSET,
                            "Data": self.BODY_TEXT,
                        },
                    },
                    "Subject": {
                        "Charset": self.CHARSET,
                        "Data": self.SUBJECT,
                    },
                },
                Source=self.SENDER,
                # If you are not using a configuration set, comment or delete the
                # following line
                # ConfigurationSetName=CONFIGURATION_SET,
            )
            # Display an error if something goes wrong.
        except ClientError as e:
            return e.response["Error"]["Message"]
        else:
            return ("Email sent! Message ID:"), (response["MessageId"])
