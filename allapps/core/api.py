from django_bolt import Router

router = Router()


@router.get("/", tags=["core"])
def greeting():
    return {"message": "Hello World"}
