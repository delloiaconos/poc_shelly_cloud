# POC: Shelly Cloud Control API - WebSocket API

A quick & small POC in Python on how to use the [Shelly Cloud Control API](https://shelly-api-docs.shelly.cloud/cloud-control-api/real-time-events#websocket-api) (and more specifically the WebSocket API) to get data from a Shelly device (tested with a Shelly Plug S + Python 3.10).

The aim is to get realtime data (temperature, power in watts) from the device directly from the Shelly Cloud, like [the official Shelly Home website](https://home.shelly.cloud/#/login), which seems to use the same API to display realtime data.

⚠️ **This is not a complete program, it was used as a POC to try to understand how the Cloud Control API worked and how the OAuth connection flow could be automated as the official documentation is lacking examples.
It doesn't have any error management, access token expiration handling, security etc.**

## How to use

Once the setup is done, the `poc.py` file will try to get OAuth credentials and fetch events through the WebSocket API. As it doesn't handle OAuth session management it will probably crash once the access token expires.

You need to:
1. In your Python environments, install the dependencies listed in `requirements.txt` (`pip install -r requirements.txt`)
2. Set two environment variables that will be used for the OAuth login:
    - `SHELLY_EMAIL` with the email you use on your Shelly Cloud account
    - `SHELLY_PASSWORD_SHA1` with the sha1 of your Shelly Cloud account password (can be obtained with `echo -n "my_password" | sha1sum` for example, or you can find it stored in the `password` field in the `user_data` entry of your browser local storage for home.shelly.cloud).
3. Change the `SERVER` variable with the server used for your account. You can obtain it by looking at the network requests done on the official Shelly Home Website. It should be something like `shelly-49-eu.shelly.cloud`. You can also find it stored in the `user_api_url` field in the `user_data` entry of your browser local storage for home.shelly.cloud.
4. You can then launch the script
