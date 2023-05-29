import re
import base64


class xwt_parsing(object):

    def __init__(self, xwt_string) -> None:
        self.__xwt_string: dict = {}

        pattern = r"^(.+)\.(.+)\.(.+)$"

        match = re.match(
            pattern, 
            xwt_string
        )

        if match:
            self.__xwt_string["header"] = base64.b64decode(
                match.group(1)
            ).decode('utf-8').replace(" ", "").replace("\n", "")

            self.__xwt_string["payload"] = base64.b64decode(
                match.group(2)
            ).decode('utf-8').replace(" ", "").replace("\n", "")

            self.__xwt_string["signature"] = base64.b64decode(
                match.group(3)
            ).decode('utf-8').replace(" ", "").replace("\n", "")


    # Parsing Header
    def __header_parsing(self) -> dict:
        header = {}

        xml_string_header = self.__xwt_string.get("header")

        # <alg>, and <type> Pattern
        alg_pattern  = r"<alg>(.*?)</alg>"
        type_pattern = r"<type>(.*?)</type>"

        # Extract <alg>, and <type> Pattern
        alg_match  = re.search(
            alg_pattern,
            xml_string_header, 
            re.DOTALL
        )

        type_match = re.search(
            type_pattern,
            xml_string_header,
            re.DOTALL
        )

        header["alg"]  = alg_match.group(1) if alg_match else None
        header["type"] = type_match.group(1) if type_match else None

        return header


    # Parsing Payload
    def __payload_parsing(self) -> dict:
        payload = {}

        xml_string_payload = self.__xwt_string.get("payload")

        # <alg>, and <type> Pattern
        uid_pattern = r"<uid>(.*?)</uid>"
        iat_pattern = r"<iat>(.*?)</iat>"

        # Extract <alg>, and <type> Pattern
        uid_match  = re.search(
            uid_pattern,
            xml_string_payload,
            re.DOTALL
        )

        iat_match  = re.search(
            iat_pattern,
            xml_string_payload,
            re.DOTALL
        )

        payload["uid"] = uid_match.group(1) if uid_match else None
        payload["iat"] = iat_match.group(1) if iat_match else None

        return payload


    # Parsing Signature
    def __signature_parsing(self) -> str:
        xml_string_signature = self.__xwt_string.get("signature")

        # <signature> Pattern
        signature_pattern = r"<signature>(.*?)</signature>"

        # Extract <alg>, and <type> Pattern
        signature_match = re.search(
            signature_pattern,
            xml_string_signature,
            re.DOTALL
        )

        return signature_match.group(1) if signature_match else None


    @property
    def parsing(self) -> dict:
        return {
            "header":    self.__header_parsing(),
            "payload":   self.__payload_parsing(),
            "signature": self.__signature_parsing()
        }


if __name__ == "__main__":

    # HEADER
    """
        XML Code :
            <header>
                <alg>HS256</alg>
                <type>XWT</type>
            <header>
    """
    HEADER_BASE64: str = "PGhlYWRlcj4KICAgPGFsZz5IUzI1NjwvYWxnPgogICA8dHlwZT5YV1Q8L3R5cGU+CjxoZWFkZXI+"



    # PAYLOAD
    """
        XML Code :
            <payload>
                <uid>H6eRhd39Hb</uid>
                <iat>1516239022</iat>
            </payload>
    """
    PAYLOAD_BASE64: str = "PHBheWxvYWQ+CiAgIDx1aWQ+SDZlUmhkMzlIYjwvdWlkPgogICA8aWF0PjE1MTYyMzkwMjI8L2lhdD4KPC9wYXlsb2FkPg=="



    # SIGNATURE
    """
        XML Code :
            <signature>
                H6eRhd39HbH6eRhd39HbH6eRhd39HbH6eRhd39Hb
            </signature>
    """
    SIGNATURE_BASE64: str = "PHNpZ25hdHVyZT4KICAgSDZlUmhkMzlIYkg2ZVJoZDM5SGJINmVSaGQzOUhiSDZlUmhkMzlIYgo8L3NpZ25hdHVyZT4="


    # Concate Header, Payload, and Signature
    xwt_string = (
        HEADER_BASE64 +
        "." +
        PAYLOAD_BASE64 +
        "." +
        SIGNATURE_BASE64
    )


    xwt = xwt_parsing(
        xwt_string = xwt_string
    )


    print(xwt.parsing)
    """
        Result (JSON) :
        {
            'header': {
                'alg': 'HS256', 
                'type': 'XWT'
            }, 
            'payload': {
                'uid': 'H6eRhd39Hb',
                'iat': '1516239022'
            },
            'signature': 'H6eRhd39HbH6eRhd39HbH6eRhd39HbH6eRhd39Hb'
        }
    """