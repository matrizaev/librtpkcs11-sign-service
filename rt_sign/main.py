import base64
import binascii

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from rt_sign.sign import perform_signing


class SignRequest(BaseModel):
    input_data: str
    user_pin: str
    key_pair_id: str


app = FastAPI()


@app.get("/")
async def root():
    """
    Root endpoint
    """
    return {"message": "Welcome to the signing service"}


@app.post("/sign")
async def sign(sign_request: SignRequest):
    """
    Sign endpoint
    """
    try:
        data: bytes = base64.b64decode(sign_request.input_data, validate=True)
    except binascii.Error as exc:
        raise HTTPException(status_code=400, detail="Invalid input data") from exc
    if not data:
        raise HTTPException(status_code=400, detail="Invalid input data")
    (result, result_size) = perform_signing(data, sign_request.user_pin.encode(), sign_request.key_pair_id.encode())
    if not result or not result_size:
        raise HTTPException(status_code=500, detail="Signing failed")
    return {"signature": base64.b64encode(result)}
