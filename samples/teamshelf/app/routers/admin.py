from fastapi import APIRouter, Depends, Path

from .. import repositories
from ..database import Database
from ..dependencies import get_db, require_admin
from ..schemas import StatusInput
from ..services import orders as service

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])


@router.get("/orders")
def list_all_orders(db: Database = Depends(get_db)):
    return {"items": repositories.find_orders(db)}


@router.patch("/orders/{order_id}/status")
def update_status(payload: StatusInput, order_id: int = Path(gt=0), db: Database = Depends(get_db)):
    return service.change_status(db, order_id, payload.status)
