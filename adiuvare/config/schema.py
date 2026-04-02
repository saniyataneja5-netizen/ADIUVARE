from pydantic import BaseModel, Field, model_validator


class SignalWeights(BaseModel):
    payload: float = Field(default=0.40, ge=0.0, le=1.0)
    behavior: float = Field(default=0.35, ge=0.0, le=1.0)
    identity: float = Field(default=0.25, ge=0.0, le=1.0)


class Thresholds(BaseModel):
    flag: float = Field(default=0.25, ge=0.0, le=1.0)
    throttle: float = Field(default=0.55, ge=0.0, le=1.0)
    block: float = Field(default=0.80, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def check_order(self):
        if not (self.flag <= self.throttle <= self.block):
            raise ValueError("thresholds are out of order")
        return self
