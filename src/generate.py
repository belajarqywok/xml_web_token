import hmac
import base64
import hashlib


class generate_xwt(object) :

    def __init__(self, header: dict, payload: list, secret_key: str) -> None:
        self.__header:    dict = header
        self.__payload:   dict = payload

        self.__secret_key: str = bytes(
            secret_key, 'utf-8'
        )


    # Get Raw Header
    def get_raw_header(self) -> str:
        # raw header
        raw_header: str = f"""
            <header>
                <alg>{self.__header.get("alg")}</alg>
                <type>{self.__header.get("type")}</type>
            </header>
        """

        return raw_header


    # Get Raw Header Encode (BASE64)
    def get_raw_header_encode(self) -> str:
        return base64.b64encode(
            self.get_raw_header().encode("utf-8")
        ).decode("utf-8")


    # Get Raw Payload
    def get_raw_payload(self) -> str:
        # raw value
        raw_value: str = ""

        # get key and value dict
        for key, value in self.__payload.items() :
            raw_value += f"""
                <{key}>{value}</{key}>
            """

        # raw Payload
        raw_payload: str = f"""
            <payload>
                {raw_value}
            </payload>
        """

        return raw_payload


    # Get Raw Payload Encode (BASE64)
    def get_raw_payload_encode(self) -> str:
        return base64.b64encode(
            self.get_raw_payload().encode("utf-8")
        ).decode("utf-8")


    # Get Signature
    def get_signature(self) -> str:
        # generate message
        message: str = (
            self.get_raw_header_encode() +
            "." +
            self.get_raw_payload_encode()
        )

        # generate signature
        signature: str = hmac.new(
            # secret key
            key = self.__secret_key,
            # message
            msg = message.encode('utf-8'), 
            # digest
            digestmod = hashlib.sha256
        )

        # raw signature
        raw_signature: str = f"""
            <signature>
                {signature.hexdigest()}
            </signature>
        """

        return raw_signature


    # Get signature Encode (BASE64)
    def get_signature_encode(self) -> str:
        return base64.b64encode(
            self.get_signature().encode("utf-8")
        ).decode("utf-8")


    # Generate Token
    @property
    def get_xwt_token(self) -> str: 
        return (
            self.get_raw_header_encode() +
            "." +
            self.get_raw_payload_encode() +
            "." +
            self.get_signature_encode()
        )
        

