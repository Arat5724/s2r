from fastapi import APIRouter, Depends

from .. import repositories
from ..database import Database
from ..dependencies import get_db, require_admin

router = APIRouter(prefix="/api/reports", tags=["reports"], dependencies=[Depends(require_admin)])


@router.get("/summary")
def summary(db: Database = Depends(get_db)):
    orders = repositories.find_orders(db)
    return {"total_orders": len(orders), "pending_orders": sum(o["status"] == "pending" for o in orders)}
