import os
import json

setup_json_def = {
    "pem":
    {
        "public": "/ssl/fullchain.pem",
        "private": "/ssl/privkey.pem"
    },
    "id_dialog": "abcdf-efghijkl-...",
    "client_secret": "passwd",
    "client_id": "dialog name"
}

def check_setup_file(prog_path):
    if os.path.isfile(prog_path+"/settings.json"):
        # Opening JSON file
        with open(prog_path+"/settings.json", 'r') as openfile:
            # Reading from json file
            json_object = json.load(openfile)

        return json_object
    else:
        # Serializing json
        json_object = json.dumps(setup_json_def, indent=4)
        
        # Writing to sample.json
        with open(prog_path+"/settings.json", "w") as outfile:
            outfile.write(json_object)

        return setup_json_def