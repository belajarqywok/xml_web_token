from src.parsing import parsing_xwt
from src.generate import (
    generate_xwt,
    generate_timestamp
)



# XWT Token Validation Class
class validation_xwt(object) :

    def __init__(self, 
        # XWT Token
        xwt_token: str, 

        # Payload Schema
        payload_schema: dict,

        # Secret Key
        secret_key: str
    ) -> None:

        # XWT Token Parsing
        self.__xwt_token_parsing: parsing_xwt = parsing_xwt(
            # XWT Token Param
            xwt_string = xwt_token,

            # Payload Schema Param
            payload_schema = payload_schema
        )

        # Secret Key
        self.__secret_key: str = secret_key



    # Timestamp Validation Checker
    def timestamp_is_valid(self, timestamp_key: str = "exp") -> bool:
        # Get XWT Token Timestamp
        get_timestamp: int = int(
            self.__xwt_token_parsing.get_all
                .get("payload")
                .get(timestamp_key)
        )

        # Get Now Timestamp
        get_now_timestamp: int = generate_timestamp().get_now_timestamp

        return get_timestamp >= get_now_timestamp



    # Signature Validation Checker
    def signature_is_valid(self) -> bool:
        # Get Payload, Header, And Signature XWT Token
        xwt_header    = self.__xwt_token_parsing.get_raw_token.get("header")
        xwt_payload   = self.__xwt_token_parsing.get_raw_token.get("payload")
        xwt_signature = self.__xwt_token_parsing.get_raw_token.get("signature")

        # Generate XWT Token For Validation
        generate_xwt_token = generate_xwt(
            secret_key = self.__secret_key
        )

        # Get XWT Token For Validation
        xwt_signature_validation = generate_xwt_token.get_signature_with_header_payload_encode(
            header  = xwt_header,
            payload = xwt_payload
        )

        return xwt_signature == xwt_signature_validation



    # Timestamp And Signature Validation Checker
    def timestamp_and_signature_is_valid(self, timestamp_key: str = "exp") -> bool:
        # Timestamp Validation
        timestamp_is_valid: bool = self.timestamp_is_valid(
            timestamp_key = timestamp_key
        )

        # Signature Validation
        signature_is_valid: bool = self.signature_is_valid()

        return timestamp_is_valid & signature_is_valid