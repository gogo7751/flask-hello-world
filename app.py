import random
from flask import Flask, jsonify, request
import os
from rediscluster import RedisCluster
from uitls import Aes_ECB, Ses
import logging


logging.getLogger().setLevel(logging.INFO)

# host = "clustercfg.redis-cluster.nhucv0.memorydb.ap-northeast-1.amazonaws.com"
# port = "6379"
# redis = RedisCluster(
#     startup_nodes=[{"host": host, "port": port}],
#     decode_responses=True,
#     skip_full_coverage_check=True,
#     ssl=True,
# )

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False


@app.route("/aes", methods=["POST"])
def hello_world():
    data = request.get_json(force=True, silent=True, cache=False)
    _input = data["input"]
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


@app.route("/otp", methods=["POST"])
def otp():
    random_num = [random.randint(0, 9) for p in range(0, 5)]
    otp = "".join(map(str, random_num))
    data = request.get_json(force=True, silent=True, cache=False)
    email = data["email"]
    body_text = f"登入驗證碼：{otp}，驗證碼 5 分鐘內有效。"
    # redis.set(f"otp-{email}", {"email": email, "otp": otp})
    # redis.expire(f"otp-{email}", 5)

    ses = Ses(email, body_text)
    res = ses.ses_send_email()
    return jsonify({"msg": res}), 200


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(force=True, silent=True, cache=False)
    otp = data["otp"]
    email = data["email"]
    otp_exist = redis.get(f"otp-{email}")
    if otp_exist:
        if otp_exist["email"] != email or otp_exist["otp"] != otp:
            return jsonify({"msg": "驗證碼錯誤"}), 401
        return jsonify({"msg": "OK"}), 200
    else:
        return jsonify({"msg": "驗證碼失效"}), 401


if __name__ == "__main__":
    app.run(debug="True", host="0.0.0.0", port=5050)
