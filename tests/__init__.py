from src.generate import generate_timestamp

# XWT Header
XWT_HEADER: dict = {
    "alg"  : "HS256",
    "type" : "XWT"
}

# Payload Schema
XWT_PAYLOAD_SCHEMA = [
    {
        "key"  : "uid", 
        "type" : "str"
    },
    {
        "key"  : "exp",
        "type" : "int"
    }
]

# XWT Payload
XWT_PAYLOAD: dict = {
    "uid" : "03108e977dc0bb921807fc16cb313151726d49bf712f6409b64541578299b11c",
    "exp" : f"""{
        generate_timestamp(hours = 1).get_expired_timedelta_timestamp
    }"""
}