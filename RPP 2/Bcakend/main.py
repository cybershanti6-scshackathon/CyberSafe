from fastapi import FastAPI

app = FastAPI(
    title="MSME Cyber Auditor - RPP.2"
)


@app.get("/")
def home():
    return {
        "message": "RPP.2 Backend is working!"
    }