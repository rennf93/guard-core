import builtins
import sys
from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def block_import(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    def blocker(module_name: str) -> None:
        real_import = builtins.__import__

        def fake_import(
            name: str,
            globals: Any = None,
            locals: Any = None,
            fromlist: Any = (),
            level: int = 0,
        ) -> Any:
            if name == module_name or name.startswith(module_name + "."):
                raise ImportError(f"No module named {module_name!r}")
            return real_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        if module_name in sys.modules:
            monkeypatch.delitem(sys.modules, module_name)

    return blocker


@pytest.fixture
def fake_transformers(monkeypatch: pytest.MonkeyPatch) -> None:
    import torch
    import transformers

    class FakeTokenizer:
        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeTokenizer":
            return cls()

        def __call__(
            self, text: Any, return_tensors: str = "pt", **_kw: Any
        ) -> dict[str, Any]:
            batch = 1 if isinstance(text, str) else len(text)
            return {"input_ids": torch.zeros((batch, 4), dtype=torch.long)}

    class FakeOutput:
        def __init__(self, logits: Any) -> None:
            self.logits = logits

    class FakeConfig:
        problem_type = "single_label_classification"
        num_labels = 2
        id2label = {0: "SAFE", 1: "INJECTION"}

    class FakeModel:
        config = FakeConfig()

        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeModel":
            return cls()

        def parameters(self) -> Any:
            yield torch.zeros(1)

        def cuda(self) -> "FakeModel":
            return self

        def __call__(self, **inputs: Any) -> FakeOutput:
            batch = inputs["input_ids"].shape[0]
            logits = torch.tensor([[1.0, 3.0]] * batch)
            return FakeOutput(logits)

    monkeypatch.setattr(transformers, "AutoTokenizer", FakeTokenizer, raising=True)
    monkeypatch.setattr(
        transformers,
        "AutoModelForSequenceClassification",
        FakeModel,
        raising=True,
    )


@pytest.fixture
def fake_transformers_sigmoid(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake transformers where the model reports a multi-label sigmoid head."""
    import torch
    import transformers

    class FakeTokenizer:
        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeTokenizer":
            return cls()

        def __call__(
            self, text: Any, return_tensors: str = "pt", **_kw: Any
        ) -> dict[str, Any]:
            batch = 1 if isinstance(text, str) else len(text)
            return {"input_ids": torch.zeros((batch, 4), dtype=torch.long)}

    class FakeOutput:
        def __init__(self, logits: Any) -> None:
            self.logits = logits

    class FakeConfig:
        problem_type = "multi_label_classification"
        num_labels = 2
        id2label = {0: "prompt_injection", 1: "toxic"}

    class FakeModel:
        config = FakeConfig()

        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeModel":
            return cls()

        def parameters(self) -> Any:
            yield torch.zeros(1)

        def cuda(self) -> "FakeModel":
            return self

        def __call__(self, **inputs: Any) -> FakeOutput:
            batch = inputs["input_ids"].shape[0]
            logits = torch.tensor([[1.0, 3.0]] * batch)
            return FakeOutput(logits)

    monkeypatch.setattr(transformers, "AutoTokenizer", FakeTokenizer, raising=True)
    monkeypatch.setattr(
        transformers,
        "AutoModelForSequenceClassification",
        FakeModel,
        raising=True,
    )


@pytest.fixture
def fake_transformers_cuda(monkeypatch: pytest.MonkeyPatch) -> None:
    import torch
    import transformers

    class CudaTensor:
        def __init__(self, t: Any) -> None:
            self._t = t
            self.shape = t.shape

        def cuda(self) -> "CudaTensor":
            return self

        def __len__(self) -> int:
            return len(self._t)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._t, name)

    class CudaParam:
        is_cuda = True

    class FakeTokenizer:
        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeTokenizer":
            return cls()

        def __call__(self, text: Any, **_kw: Any) -> dict[str, Any]:
            batch = 1 if isinstance(text, str) else len(text)
            return {"input_ids": CudaTensor(torch.zeros((batch, 4), dtype=torch.long))}

    class FakeOutput:
        def __init__(self, logits: Any) -> None:
            self.logits = logits

    class FakeModel:
        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeModel":
            return cls()

        def parameters(self) -> Any:
            yield CudaParam()

        def cuda(self) -> "FakeModel":
            return self

        def __call__(self, **inputs: Any) -> FakeOutput:
            batch = inputs["input_ids"].shape[0]
            return FakeOutput(torch.tensor([[1.0, 3.0]] * batch))

    monkeypatch.setattr(transformers, "AutoTokenizer", FakeTokenizer)
    monkeypatch.setattr(transformers, "AutoModelForSequenceClassification", FakeModel)


@pytest.fixture
def fake_long_input_transformers(
    monkeypatch: pytest.MonkeyPatch,
) -> list[list[float]]:
    import torch
    import transformers

    logits_queue: list[list[float]] = []

    class FakeTokenizer:
        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeTokenizer":
            return cls()

        def __call__(
            self,
            text: Any,
            return_tensors: str | None = None,
            **_kw: Any,
        ) -> dict[str, Any]:
            if return_tensors == "pt":
                batch = 1 if isinstance(text, str) else len(text)
                return {"input_ids": torch.zeros((batch, 4), dtype=torch.long)}
            if isinstance(text, str):
                return {"input_ids": list(range(len(text)))}
            return {"input_ids": [list(range(len(t))) for t in text]}

        def decode(self, ids: list[int], **_kw: Any) -> str:
            return "x" * len(ids)

    class FakeOutput:
        def __init__(self, logits: Any) -> None:
            self.logits = logits

    class FakeModel:
        @classmethod
        def from_pretrained(cls, name: str, **_kw: Any) -> "FakeModel":
            return cls()

        def parameters(self) -> Any:
            yield torch.zeros(1)

        def cuda(self) -> "FakeModel":
            return self

        def __call__(self, **inputs: Any) -> FakeOutput:
            batch = inputs["input_ids"].shape[0]
            logits = logits_queue.pop(0) if logits_queue else [1.0, 3.0]
            return FakeOutput(torch.tensor([logits] * batch))

    monkeypatch.setattr(transformers, "AutoTokenizer", FakeTokenizer)
    monkeypatch.setattr(transformers, "AutoModelForSequenceClassification", FakeModel)
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    return logits_queue
