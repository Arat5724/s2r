from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginInput(StrictInput):
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=1, max_length=128)


class OrderInput(StrictInput):
    product_id: int = Field(gt=0, strict=True)
    quantity: int = Field(ge=1, le=20, strict=True)
    note: str = Field(default="", max_length=300)


class StatusInput(StrictInput):
    status: Literal["approved", "rejected"]
