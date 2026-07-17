from django_bolt import BoltAPI

api = BoltAPI()


@api.get("/")
def greeting():
    return {"message": "Hello World"}
