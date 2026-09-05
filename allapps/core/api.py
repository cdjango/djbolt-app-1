from django_bolt import Router

router = Router()


@router.get("/")
def greeting():
    return {"message": "Hello World"}
