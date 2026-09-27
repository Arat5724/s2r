from datetime import datetime, timezone

from fastapi import HTTPException

from .. import repositories
from ..database import Database
from ..schemas import OrderInput


def visible_order(db: Database, order_id: int, user: dict):
    order = repositories.order_by_id(db, order_id)
    if order is None or (order["user_id"] != user["id"] and user["role"] != "admin"):
        raise HTTPException(404, "주문을 찾을 수 없습니다.")
    return order


def create_order(db: Database, payload: OrderInput, user: dict):
    if repositories.product_by_id(db, payload.product_id) is None:
        raise HTTPException(404, "상품을 찾을 수 없습니다.")
    oid = repositories.insert_order(db, user["id"], payload.product_id, payload.quantity,
                                     payload.note, datetime.now(timezone.utc).isoformat())
    return repositories.order_by_id(db, oid)


def cancel_order(db: Database, order_id: int, user: dict):
    order = visible_order(db, order_id, user)
    if order["user_id"] != user["id"]:
        raise HTTPException(403, "본인의 주문만 취소할 수 있습니다.")
    return change_status(db, order_id, "cancelled")


def change_status(db: Database, order_id: int, status: str):
    if repositories.order_by_id(db, order_id) is None:
        raise HTTPException(404, "주문을 찾을 수 없습니다.")
    if not repositories.transition_order(db, order_id, status):
        raise HTTPException(409, "대기 중인 주문만 변경할 수 있습니다.")
    return repositories.order_by_id(db, order_id)
