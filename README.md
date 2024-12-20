# SkyNest
SkyNest is a bad copy of Bluesky.

What is the purpose of this application?
Try to test all capabilities such as secure user authorization, web design, Apis, captcha security, front line security and responsive pages.

Stack:
- Web Framework: Gunicorn + Flask
- Rendering: Jinja2
- Database: Redis + local files
- Security: PoW + Image Captchas + IP Check + Beam IDs

## 🚀 Installation
Install git: `sudo apt install git`
Install python: `sudo apt install python3.11`

1. Install it via `git clone https://github.com/tn3w/SkyNest` or download the zip [here](https://github.com/tn3w/SkyNest/archive/refs/heads/master.zip).
2. Go into SkyNest: `cd SkyNest`
3. Create an virtual env with `python3 -m venv .venv` and `source .venv/bin/activate`
4. Install pip requirements `pip install -r requirements.txt`
5. Setting up Redis:
```bash
sudo apt-get update
sudo apt-get install redis -y
sudo systemctl enable redis-server.service
sudo systemctl start redis-server.service
```
6. Starting SkyNest: `python main.py`

Quick command:
```bash
git clone https://github.com/tn3w/SkyNest; cd SkyNest; python3 -m venv .venv; source .venv/bin/activate; pip install -r requirements.txt; sudo apt-get update; sudo apt-get install redis -y; sudo systemctl enable redis-server.service; sudo systemctl start redis-server.service; python main.py
```

## Configuration:
SkyNest offers various configuration options:
- `HOST`: Specifies the hostname or IP address on which the Gunicorn server will listen for incoming requests. (Default: 127.0.0.1)
- `PORT`: Defines the port number on which the Gunicorn server will listen for incoming requests. (Default: 8080)
- `WORKERS`: Sets the number of worker processes that Gunicorn will spawn to handle incoming requests. (Default: 16)
- `CERT_FILE_PATH`: Specifies the file path to the SSL certificate for secure connections. (Default: None)
- `KEY_FILE_PATH`: Specifies the file path to the SSL key for secure connections. (Default: None)
- `POW_DIFFICULTY`: Sets the difficulty level for proof of work calculations. (Default: 5)
- `ACCESS_TOKEN`: Used to provide an additional layer of security during development by requiring an access token to view the application. (Default: None)
- `DEFAULT_LANGUAGE`: Specifies the default language for the application, which can be used for language fallback. (Default: en)
- `REQUIRED_LANGUAGE`: Indicates a specific language that the application should use, bypassing the default language check. (Default: None)
- `CREATOR`: Determines whether to display a creator name in the application. (Default: None)