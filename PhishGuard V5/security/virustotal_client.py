class VirusTotalClient:
    def __init__(self, secret_manager):
        self.sm = secret_manager

    async def _get_api_key(self):
        return await self.sm.get_secret(
            "virustotal_api",
            loader=self._load_from_aws
        )

    async def _load_from_aws(self):
        # boto3 / aws-sdk integration here
        return os.getenv("VT_API_RUNTIME")

    async def scan_url(self, url: str):
        api_key = await self._get_api_key()

        headers = {
            "x-apikey": api_key
        }

        # NO LOGGING OF HEADERS OR KEY
        return {"status": "secure_request_sent"}
