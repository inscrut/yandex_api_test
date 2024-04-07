import json

true = True
false = False

reqid = "0"

def get_dev_list():
    device_list = {
        "request_id": reqid,
        "payload": {
            "user_id": "Neodim-iot-device-esp32",
            "devices": [
                {
                    "id": "ESP32-led",
                    "name": "Плата разработки",
                    "description": "ESP32",
                    "room": "Гостиная",
                    "type": "devices.types.light",
                    "custom_data": {
                        "api_location": "rus",
                        "pin": 2
                    },
                    "capabilities": [
                        {
                            "type": "devices.capabilities.on_off",
                            "retrievable": true,
                            "reportable": true
                        }
                    ],
                    "device_info": {
                        "manufacturer": "Neodim IoT",
                        "model": "ESP32",
                        "hw_version": "1.0",
                        "sw_version": "1.0"
                    }
                }
            ]
        }
    }
    return device_list