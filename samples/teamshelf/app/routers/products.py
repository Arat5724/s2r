from fastapi import APIRouter, Depends, HTTPException, Path, Query

from .. import repositories
from ..database import Database
from ..dependencies import get_db

router = APIRouter(prefix="/api/products", tags=["products"])


@router.get("")
def list_products(q: str = Query(default="", max_length=80),
                  category: str | None = Query(default=None, max_length=20),
                  db: Database = Depends(get_db)):
    return {"items": repositories.find_products(db, q, category)}


@router.get("/{product_id}")
def product_detail(product_id: int = Path(gt=0), db: Database = Depends(get_db)):
    product = repositories.product_by_id(db, product_id)
    if product is None:
        raise HTTPException(404, "상품을 찾을 수 없습니다.")
    return product
