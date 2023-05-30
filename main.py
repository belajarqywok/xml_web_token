from src.parsing import parsing_xwt
from src.generate import generate_xwt


generate = generate_xwt(
    header = {
        "alg"  : "HS256",
        "type" : "XWT"
    },

    payload = {
        "uid" : "H6eRhd39Hb",
        "iat" : "1516239022"
    },

    secret_key = "SECRET_KEY121"
)


if __name__ == "__main__":
    # Get XWT Token
    xwt_string = generate.get_xwt_token
    print(xwt_string)

    # Parsing XWT
    xwt = parsing_xwt(
        xwt_string = xwt_string,
        payload_schema = [
            {
                "key"  : "uid", 
                "type" : "str"
            },
            {
                "key"  : "iat",
                "type" : "int"
            }
        ]
    )


    # Get All Data
    print(f"Get All Data : {xwt.get_all}\n")

    # Get Raw Token
    print(f"Get Raw Token : {xwt.get_raw_token}\n")

    # Get Raw XML
    print(f"Get Raw XML : {xwt.get_raw_xml}")