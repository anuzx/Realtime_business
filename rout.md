pip install securelog-sdk

Setup — one line in your existing FastAPI app
pythonfrom fastapi import FastAPI
from securelog_sdk import instrument

app = FastAPI()

instrument(
app,
api_key=“sk_your_key_here”,
base_url=“https://securelog.pulseguard.com”
)