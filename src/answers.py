import json

true = True
false = False

_answer_q = {
    "request_id": "",
    "payload": {
        "devices":[

        ]  
    }
}

_answer_act = {
    "request_id": "",
    "payload": {
      "devices": []
    }
}

_ans_dev = {
    "devices": [
        {
            "id": "",
            "capabilities": [
            {
                "type": "",
                "state": {
                    "instance": "on",
                    "value": false,
                    "action_result": {
                        "status": "",
                        "error_code": "",
                        "error_message": ""
                    }
                }
            }
            ]
        }     
    ] 
}

_answer_dl = {
  "request_id": "",
  "payload": {
      "user_id": "",
      "devices": []
  }
}

def reset_ans_query():
    global _answer_q
    _answer_q = {
        "request_id": "",
        "payload": {
            "devices":[

            ]  
        }
    }

def build_device_query(dev_name, _cap="", _prop=""):
    _dev = {
        "id": dev_name,
        "capabilities": [

        ],
        "properties": [

        ]
    }
    _dev["id"] = dev_name
    return _dev

def build_ans_query(_reqid, _list_devs_json):
    global _answer_q

    _answer_q["request_id"] = _reqid

    data = json.dumps(_answer_q)

    for item in _list_devs_json:
        data["payload"]["devices"].append(item)

    return data

