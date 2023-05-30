import os
import unittest
from dotenv import load_dotenv

from src.parsing import parsing_xwt
from src.generate import generate_xwt


class utility_tests(unittest.TestCase) :

    load_dotenv()

    # Generate Token
    generate_xwt_token = generate_xwt(
        header = {
            "alg"  : "HS256",
            "type" : "XWT"
        },

        payload = {
            "uid" : "H6eRhd39Hb",
            "iat" : "1516239022"
        },

        secret_key = os.environ.get("SECRET_KEY")
    )

    # Generate Fake Token
    generate_xwt_fake_token = generate_xwt(
        header = {
            "alg"  : "HS256",
            "type" : "XWT"
        },

        payload = {
            "uid" : "H6eRhd39Hb",
            "iat" : "1516239022"
        },

        secret_key = os.environ.get("FAKE_SECRET_KEY")
    )


    # Testing assertion fake token
    def test_this_is_fake_token (self) -> None :
        # Create Tokens
        token = self.generate_xwt_token.get_xwt_token
        fake_token = self.generate_xwt_fake_token.get_xwt_token

        # Payload Schema
        schema = [
            {
                "key"  : "uid", 
                "type" : "str"
            },
            {
                "key"  : "iat",
                "type" : "int"
            }
        ]

        # Parsing Tokens
        xwt_token = parsing_xwt(
            xwt_string = token,
            payload_schema = schema
        )

        fake_xwt_token = parsing_xwt(
            xwt_string = fake_token,
            payload_schema = schema
        )

        self.assertNotEquals(
            xwt_token.get_all.get("signature"),
            fake_xwt_token.get_all.get("signature")
        )