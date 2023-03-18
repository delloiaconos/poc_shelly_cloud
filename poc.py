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
            power FLOAT  NOT NULL,
            overpower BOOL  NOT NULL,
            temperature FLOAT  NOT NULL,
            over_temperature BOOL  NOT NULL
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
    database_cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs(
            timestamp_utc INTEGER  NOT NULL PRIMARY KEY,
            power FLOAT  NOT NULL,
            overpower BOOL  NOT NULL,
            temperature FLOAT  NOT NULL,
            over_temperature BOOL  NOT NULL
        )
    """
    )
    database_connection.commit()

    print("Connecting to websocket")
    async for websocket in websockets.connect(websocket_url):
        print("Connected")
        try:
            async for message in websocket:
                print(f"Processing message received at {datetime.now(timezone.utc)}")
                parsed_message = json.loads(message)
                power = parsed_message["status"]["meters"][0]["power"]
                timestamp = parsed_message["status"]["meters"][0]["timestamp"]
                overpower = parsed_message["status"]["meters"][0]["overpower"]
                temperature = parsed_message["status"]["temperature"]
                over_temperature = parsed_message["status"]["overtemperature"]

                # Insert in database
                database_cursor.execute(
                    """
                    INSERT INTO logs(
                        timestamp_utc,
                        power,
                        overpower,
                        temperature,
                        over_temperature
                    )
                    VALUES(?, ?, ?, ?, ?)
                """,
                    (timestamp, power, overpower, temperature, over_temperature),
                )
                database_connection.commit()

        except websockets.ConnectionClosed as err:
            print(f"Error on websocket: {err}, reconnecting...")
            continue


if __name__ == "__main__":
    asyncio.run(main())
