from fastapi import APIRouter, Depends, Path

from .. import repositories
from ..database import Database
from ..dependencies import current_user, get_db
from ..schemas import OrderInput
from ..services import orders as service

router = APIRouter(prefix="/api/orders", tags=["orders"])


@router.get("")
def list_orders(user: dict = Depends(current_user), db: Database = Depends(get_db)):
    return {"items": repositories.find_orders(db, user["id"])}


@router.post("", status_code=201)
def submit_order(payload: OrderInput, user: dict = Depends(current_user), db: Database = Depends(get_db)):
    return service.create_order(db, payload, user)


@router.get("/{order_id}")
def order_detail(order_id: int = Path(gt=0), user: dict = Depends(current_user), db: Database = Depends(get_db)):
    return service.visible_order(db, order_id, user)


@router.post("/{order_id}/cancel")
def cancel(order_id: int = Path(gt=0), user: dict = Depends(current_user), db: Database = Depends(get_db)):
    return service.cancel_order(db, order_id, user)
