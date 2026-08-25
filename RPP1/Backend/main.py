from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from schemas import PasswordPolicyRequest
from rpp_checker import check_rpp_policy


app = FastAPI(
    title="MSME Cyber Scanner",
    description="RPP.1 Robust Password Policy Compliance Checker"
)


# -----------------------------------------
# ENABLE FRONTEND CONNECTION
# -----------------------------------------

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# -----------------------------------------
# HOME API
# -----------------------------------------

@app.get("/")
def home():

    return {
        "message": "MSME Cyber Scanner API is running"
    }


# -----------------------------------------
# RPP.1 SCANNER API
# -----------------------------------------

@app.post("/scan/rpp1")
def scan_rpp1(policy: PasswordPolicyRequest):

    result = check_rpp_policy(policy)

    return result