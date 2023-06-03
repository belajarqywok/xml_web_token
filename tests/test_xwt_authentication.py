import os
import unittest
from dotenv import load_dotenv

from . import (
    # XWT Header
    XWT_HEADER,

    # XWT Payload
    XWT_PAYLOAD,

    # XWT Payload Schema
    XWT_PAYLOAD_SCHEMA
)

from src.parsing import parsing_xwt
from src.validation import validation_xwt

from src.generate import (
    generate_xwt,
    generate_timestamp
)


class authentication_tests(unittest.TestCase) :

    # Load Environment Variables
    load_dotenv()

    ### Fake Signature Testing ###
    def test_fake_xwt_token_signature(self) -> None:
        # Generate Real & Fake XWT Token
        generate_real_xwt_token = generate_xwt(
            # XWT Header Param
            header  = XWT_HEADER,

            # XWT Payload Param
            payload = XWT_PAYLOAD,

            # XWT Secret Key Param
            secret_key = os.environ.get("SECRET_KEY")
        )

        generate_fake_xwt_token = generate_xwt(
            # XWT Header Param
            header  = XWT_HEADER,

            # XWT Payload Param
            payload = XWT_PAYLOAD,

            # XWT Secret Key Param
            secret_key = os.environ.get("FAKE_SECRET_KEY")
        )

        # Get XWT Tokens
        real_token = generate_real_xwt_token.get_xwt_token
        fake_token = generate_fake_xwt_token.get_xwt_token

        # Parsing XWT Tokens
        real_xwt_token = parsing_xwt(
            xwt_string = real_token,
            payload_schema = XWT_PAYLOAD_SCHEMA
        )

        fake_xwt_token = parsing_xwt(
            xwt_string = fake_token,
            payload_schema = XWT_PAYLOAD_SCHEMA
        )

        # Assert Real and Fake XWT Tokens
        self.assertNotEquals(
            # Real XWT Token
            real_xwt_token.get_all.get("signature"),

            # Fake XWT Token
            fake_xwt_token.get_all.get("signature")
        )




    ### Real Signature Testing ###
    def test_real_xwt_token_signature(self) -> None:
        # Generate Real XWT Token
        generate_real_xwt_token = generate_xwt(
            # XWT Header Param
            header  = XWT_HEADER,

            # XWT Payload Param
            payload = XWT_PAYLOAD,

            # XWT Secret Key Param
            secret_key = os.environ.get("SECRET_KEY")
        )

        # Get Real XWT Token
        real_xwt_token = generate_real_xwt_token.get_xwt_token


        ##############################
        ##### Validate XWT Token #####
        ##############################


        # Parsing Real XWT Token
        parsing_xwt_token = parsing_xwt(
            xwt_string = real_xwt_token,
            payload_schema = XWT_PAYLOAD_SCHEMA
        )

        # Get Payload, Header, And Signature Real XWT Token
        real_xwt_header     = parsing_xwt_token.get_raw_token.get("header")
        real_xwt_payload    = parsing_xwt_token.get_raw_token.get("payload")
        real_xwt_signature  = parsing_xwt_token.get_raw_token.get("signature")


        # Generate XWT Token For Validation
        generate_validation_xwt_token = generate_xwt(
            secret_key = os.environ.get("SECRET_KEY")
        )

        # Get XWT Token For Validation
        xwt_signature_validation = generate_validation_xwt_token.get_signature_with_header_payload_encode(
            header  = real_xwt_header,
            payload = real_xwt_payload
        )

        self.assertEquals(
            real_xwt_signature,
            xwt_signature_validation
        )




    ### Expired Token Testing
    def test_expired_token(self) -> None:
        # Expired Timestamp
        expired_timestamp: int = generate_timestamp(
            hours = -1
        ).get_now_timestamp

        # Edited Exist Payload
        edited_payload: dict = XWT_PAYLOAD
        edited_payload["exp"] = str(expired_timestamp)

        # Generate Real XWT Token
        generate_xwt_token = generate_xwt(
            # XWT Header Param
            header = XWT_HEADER,

            # Edited XWT Payload Param
            payload = edited_payload,

            # XWT Secret Key Param
            secret_key = os.environ.get("SECRET_KEY")
        )

        # Parsing XWT Token
        parsing_xwt_token = parsing_xwt(
            xwt_string = generate_xwt_token.get_xwt_token,
            payload_schema = XWT_PAYLOAD_SCHEMA
        )

        # Get XWT Token Timestamp
        xwt_token_timestamp: int = int(
            parsing_xwt_token.get_all
                .get("payload")
                .get("exp")
        )

        self.assertFalse(
            xwt_token_timestamp > (
                generate_timestamp().get_now_timestamp
            )
        )




    ### XWT Token Validation Testing
    def test_validation_token(self) -> None:
        # Updated Timestamp
        updated_timestamp: int = generate_timestamp(
            hours = 1
        ).get_expired_timedelta_timestamp

        # Edited Exist Payload
        edited_payload: dict = XWT_PAYLOAD
        edited_payload["exp"] = str(updated_timestamp)

        # Generate Real XWT Token
        generate_xwt_token = generate_xwt(
            # XWT Header Param
            header = XWT_HEADER,

            # Edited XWT Payload Param
            payload = edited_payload,

            # XWT Secret Key Param
            secret_key = os.environ.get("SECRET_KEY")
        )

        # Checking Timestamp Validation
        token_validation: object = validation_xwt(
            # XWT Token Param
            xwt_token = generate_xwt_token.get_xwt_token,

            # Payload Schema Param
            payload_schema = XWT_PAYLOAD_SCHEMA,
            # Secret Key Param
            secret_key = os.environ.get("SECRET_KEY")
        )

        self.assertTrue(
            token_validation.timestamp_is_valid() &
            token_validation.signature_is_valid() &
            token_validation.timestamp_and_signature_is_valid()
        )
