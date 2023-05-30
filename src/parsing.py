import re
import base64


class parsing_xwt(object):

    def __init__(self, xwt_string: str = "", payload_schema: list = []) -> None:
        # Parsing Raw Token and XML
        self.__raw_xml:   dict = {}
        self.__raw_token: dict = {}

        pattern = r"^(.+)\.(.+)\.(.+)$"
        match = re.match(
            pattern, 
            xwt_string
        )

        if match:
            # Parsing Raw Token and XML Header
            self.__raw_xml["header"] = base64.b64decode(
                match.group(1)
            ).decode('utf-8')

            self.__raw_token["header"] = match.group(1)


            # Parsing Raw Token and XML Payload
            self.__raw_xml["payload"] = base64.b64decode(
                match.group(2)
            ).decode('utf-8')

            self.__raw_token["payload"] = match.group(2)


            # Parsing Raw Token and XML Signature
            self.__raw_xml["signature"] = base64.b64decode(
                match.group(3)
            ).decode('utf-8')

            self.__raw_token["signature"] = match.group(3)


        # Declare Payload Schema
        self.__payload_schema: list = payload_schema


    # Parsing Header
    def __header_parsing(self) -> dict:
        header = {}

        xml_string_header: str = (
            self.__raw_xml["header"]
                .strip()
                .replace("\n", "")
        )

        # <alg>, and <type> Pattern
        alg_pattern:  str = r"<alg>(.*?)</alg>"
        type_pattern: str = r"<type>(.*?)</type>"

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

        xml_string_payload: str = (
            self.__raw_xml["payload"]
                .strip()
                .replace("\n", "")
        )
                

        for schema in self.__payload_schema :
            # Schema Pattern
            schema_pattern = fr"<{schema.get('key')}>(.*?)</{schema.get('key')}>"

            # Extract Schema Pattern
            schema_match = re.search(
                schema_pattern,
                xml_string_payload,
                re.DOTALL
            )

            if schema.get('type') == "str" :
                payload[schema.get('key')] = schema_match.group(1) if schema_match else None

            elif schema.get('type') == "int" :
                payload[schema.get('key')] = int(schema_match.group(1) if schema_match else None)

            elif schema.get('type') == "float" :
                payload[schema.get('key')] = float(schema_match.group(1) if schema_match else None)

        return payload



    # Parsing Signature
    def __signature_parsing(self) -> str:
        xml_string_signature: str = (
            self.__raw_xml["signature"]
                .replace(" ", "")
                .replace("\n", "")
        )

        # <signature> Pattern
        signature_pattern = r"<signature>(.*?)</signature>"

        # Extract <signature> Pattern
        signature_match = re.search(
            signature_pattern,
            xml_string_signature,
            re.DOTALL
        )

        return signature_match.group(1) if signature_match else None



    # Get Raw XML
    @property
    def get_raw_xml(self) -> dict :
        return self.__raw_xml


    # Get Raw Token
    @property
    def get_raw_token(self) -> dict :
        return self.__raw_token


    @property
    def get_all(self) -> dict:
        return {
            "header":    self.__header_parsing(),
            "payload":   self.__payload_parsing(),
            "signature": self.__signature_parsing()
        }