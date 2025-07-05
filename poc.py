import asyncio
from datetime import datetime
import requests
import websockets
import json
import sqlite3
import os
from datetime import timezone


EMAIL = os.environ["SHELLY_EMAIL"]
PASSWORD_SHA1 = os.environ["SHELLY_PASSWORD_SHA1"]
SERVER = "shelly-49-eu.shelly.cloud"
SQLITE_DATABASE = "shelly_plug.db"


def _get_authorization_code():
    """
    Get authorization code for OAuth2.

    This mimics the request done by the official OAuth login webpage.
    """
    res = requests.post(
        "https://api.shelly.cloud/oauth/login",
        data={
            "email": EMAIL,
            "password": PASSWORD_SHA1,
            "response_type": "",
            "client_id": "shelly-diy",
        },
    )

    # TODO: add error management
    if not res.json().get("isok", True):
        print(f"Error on login: {res.json()}")

    return res.json()["data"]["code"]


def login():
    """Login on the API."""
    res = requests.post(
        f"https://{SERVER}/oauth/auth",
        data={
            "client_id": "shelly-diy",
            "grant_type": "code",
            "code": _get_authorization_code(),
        },
    )

    # TODO: add error management
    return res.json()


def create_table(database_cursor):
    database_cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs(
            timestamp_utc INTEGER  NOT NULL PRIMARY KEY,
            time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            name TEXT  NOT NULL,
            power FLOAT  NOT NULL,
            voltage FLOAT  NOT NULL,
            pf FLOAT  NOT NULL,
            reactive FLOAT  NOT NULL,
            total FLOAT  NOT NULL
        )
        """
    )


async def main():
    # TODO: add token renewal
    print("Login...")
    oauth_informations = login()
    access_token = oauth_informations["access_token"]
    websocket_url = f"wss://{SERVER}:6113/shelly/wss/hk_sock?t={access_token}"

    print("Opening local database...")
    database_connection = sqlite3.connect(SQLITE_DATABASE)
    database_cursor = database_connection.cursor()

    # Create table
    create_table( database_cursor )
    database_connection.commit()

    print("Connecting to websocket")
    async for websocket in websockets.connect(websocket_url):
        print("Connected")
        try:
            async for message in websocket:
                #print(f"Processing message received at {datetime.now(timezone.utc)} {message}")
                parsed_message = json.loads(message)

                if 'metadata' not in parsed_message or  'status' not in parsed_message:
                    print("No valid message, skipping...")
                    continue
                
                for idx, metadata in enumerate(parsed_message['metadata']):
                    if 'purpose' not in metadata:
                        print( f"No purpose found in {message}" )
                        break
                    
                    if metadata['purpose'] == 'emeter':         
                        try:
                            name = str(metadata['name']).strip()
                            power = parsed_message['status']['emeters'][idx]["power"]
                            reactive = parsed_message['status']['emeters'][idx]["reactive"]
                            pf = parsed_message['status']['emeters'][idx]["pf"]
                            voltage = parsed_message['status']['emeters'][idx]["voltage"]
                            total = parsed_message['status']['emeters'][idx]["total"]
                        except:
                            print(f"Error parsing message: {parsed_message}, skipping...")
                            continue
                        timestamp = datetime.now(timezone.utc)
                        print( f"{timestamp}, Name: {name}, Power: {power}, Reactive: {reactive}, pf: {pf}, Voltage: {voltage}, Total: {total}" )
                        # Insert in database

                        try:
                            database_cursor.execute(
                            """
                                INSERT INTO logs( timestamp_utc, time, name, power, voltage, pf, reactive, total )
                                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                                ( int(timestamp.strftime('%Y%m%d%H%M%S')), 
                                  timestamp, 
                                  name, 
                                  power, 
                                  voltage, 
                                  pf, 
                                  reactive, 
                                  total
                                ),
                            )
                            database_connection.commit()
                        except:
                            continue

        except websockets.ConnectionClosed as err:
            print(f"Error on websocket: {err}, reconnecting...")
            continue


if __name__ == "__main__":
    asyncio.run(main())
