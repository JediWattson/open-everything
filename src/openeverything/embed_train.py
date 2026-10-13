"""Embedder fine-tune: LoRA on Qodo over contrastive triplets.

Two data sources feed the same loss:
  - mksft --emb  (asm anchor -> source positive)   — semantic grounding
  - mkemb        (asm anchor -> same-community asm) — structural grouping

Loss is multiple-negatives-ranking: anchor must rank its positive above
the other positives + explicit negatives in the batch. Train on MPS with
a bf16 base and fp32 LoRA grads — fits 16 GB at small batch sizes.
"""

from __future__ import annotations

import json
from pathlib import Path

from .embed import _force_bidirectional

_SCALE = 20.0  # MNRL temperature


def _save_adapter(model, lconf, model_name: str, out_dir: Path) -> None:
    """Emit just the LoRA tensors as a peft-loadable adapter dir.

    peft's save_pretrained dumps merged weights on this stack — emit the
    adapter files explicitly instead."""
    from safetensors.torch import save_file

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sd = {
        "base_model.model." + k: v.cpu()
        for k, v in model[0].auto_model.state_dict().items()
        if ".lora_" in k
    }
    save_file(sd, out_dir / "adapter_model.safetensors")
    (out_dir / "adapter_config.json").write_text(json.dumps({
        "peft_type": "LORA",
        "base_model_name_or_path": model_name,
        "r": lconf.r, "lora_alpha": lconf.lora_alpha,
        "lora_dropout": lconf.lora_dropout, "bias": "none",
        "target_modules": list(lconf.target_modules),
        "task_type": "FEATURE_EXTRACTION",
    }))
    (out_dir / "base_model.txt").write_text(model_name)


def _save_checkpoint(model, lconf, model_name, opt, step, ckpt_dir) -> None:
    _save_adapter(model, lconf, model_name, ckpt_dir)
    import torch
    torch.save(opt.state_dict(), ckpt_dir / "optimizer.pt")
    (ckpt_dir / "trainer_state.json").write_text(
        json.dumps({"step": step}))


def _load_checkpoint(model, opt, ckpt_dir, device) -> int:
    from safetensors.torch import load_file
    import torch

    ckpt_dir = Path(ckpt_dir)
    sd = {
        k.removeprefix("base_model.model."): v.to(device)
        for k, v in load_file(ckpt_dir / "adapter_model.safetensors").items()
    }
    model[0].auto_model.load_state_dict(sd, strict=False)
    opt_file = ckpt_dir / "optimizer.pt"
    if opt_file.exists():
        opt.load_state_dict(torch.load(opt_file, weights_only=True))
        for st in opt.state.values():
            for k, v in st.items():
                if isinstance(v, torch.Tensor):
                    st[k] = v.to(device)
    state = json.loads((ckpt_dir / "trainer_state.json").read_text())
    return int(state["step"])


def load_triplets(paths: list[Path]) -> list[list[str]]:
    rows = []
    for p in paths:
        for line in Path(p).read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            if d.get("anchor") and d.get("positive"):
                rows.append([d["anchor"], d["positive"],
                           d.get("negative", "")])
    return rows


def load_labeled(paths: list[Path]) -> dict[str, list[str]]:
    """{label, text} rows -> label -> member texts (supervised contrastive)."""
    from collections import defaultdict

    groups: dict[str, list[str]] = defaultdict(list)
    for p in paths:
        for line in Path(p).read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            if d.get("label") and d.get("text"):
                groups[d["label"]].append(d["text"])
    return {k: v for k, v in groups.items() if len(v) >= 2}


def train(
    pair_paths: list[Path],
    out_dir: Path,
    model_name: str,
    epochs: int = 1,
    batch_size: int = 1,
    lr: float = 2e-5,
    max_len: int = 1024,
    device: str = "mps",
    ckpt_every: int = 0,
    resume: Path | None = None,
    on_progress=None,
) -> Path:
    import torch
    import torch.nn.functional as F
    from torch.utils.data import DataLoader
    from sentence_transformers import SentenceTransformer
    from peft import LoraConfig, get_peft_model

    labeled = load_labeled(pair_paths)
    rows = load_triplets(pair_paths)
    if not labeled and not rows:
        raise ValueError("no triplets or labeled rows loaded")

    model = SentenceTransformer(
        model_name, trust_remote_code=False, device=device
    )
    _force_bidirectional(model[0].auto_model)
    lconf = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model[0].auto_model = get_peft_model(model[0].auto_model, lconf)
    if device == "mps":
        # post-load cast: dtype-at-load hits pathological per-tensor copies
        model = model.to(torch.bfloat16)
    # training activations dwarf inference memory — checkpoint + cap docs
    model[0].auto_model.gradient_checkpointing_enable()
    model[0].auto_model.enable_input_require_grads()
    model.max_seq_length = max_len
    model.train()

    from sentence_transformers import InputExample

    trainable = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(trainable, lr=lr)
    step = _load_checkpoint(model, opt, resume, device) if resume else 0

    def _to_dev(feats):
        return [
            {k: v.to(device) if isinstance(v, torch.Tensor) else v
             for k, v in f.items()}
            for f in feats
        ]

    def _after_step(loss):
        nonlocal step
        step += 1
        if on_progress:
            on_progress(step, steps, float(loss.detach()))
        if ckpt_every and step % ckpt_every == 0:
            _save_checkpoint(
                model, lconf, model_name, opt, step,
                Path(out_dir) / f"checkpoint-{step}")

    if labeled:
        # SupCon: each step samples communities x members; every same-label
        # batchmate is a positive, everything else a negative. Multi-positive
        # pressure — pulls communities together instead of pushing apart.
        import random
        rng = random.Random(0)
        labels = sorted(labeled)
        total = sum(len(v) for v in labeled.values())
        comms, members = 2, max(2, batch_size // 2)
        steps = epochs * max(1, total // (comms * members))
        for ep in range(epochs):
            for _ in range(max(1, total // (comms * members))):
                batch, labs = [], []
                for li, lab in enumerate(rng.sample(labels, comms)):
                    pool = labeled[lab]
                    picks = [rng.choice(pool) for _ in range(members)]
                    batch.extend(picks)
                    labs.extend([li] * members)
                feats, _ = model.smart_batching_collate(
                    [InputExample(texts=[t]) for t in batch])
                z = F.normalize(
                    model(_to_dev(feats)[0])["sentence_embedding"], dim=-1)
                same = torch.tensor(labs, device=device)[:, None] == \
                    torch.tensor(labs, device=device)[None, :]
                same.fill_diagonal_(False)
                logits = z @ z.T * _SCALE
                logits.fill_diagonal_(-torch.inf)
                logprob = logits - torch.logsumexp(
                    logits, 1, keepdim=True)
                # masked_fill, not *same: -inf * 0 is NaN at masked positions
                pos = logprob.masked_fill(~same, 0).sum(1) / \
                    same.sum(1).clamp(min=1)
                loss = -pos[same.sum(1) > 0].mean()
                opt.zero_grad()
                loss.backward()
                opt.step()
                _after_step(loss)
    else:
        loader = DataLoader(
            [InputExample(texts=r) for r in rows],
            batch_size=batch_size, shuffle=True, drop_last=True,
            collate_fn=model.smart_batching_collate,
        )
        steps = epochs * len(loader)
        for ep in range(epochs):
            for feats, _labels in loader:
                feats = _to_dev(feats)[:3]
                a, p, n = [
                    F.normalize(model(f)["sentence_embedding"], dim=-1)
                    for f in feats
                ]
                scores = a @ torch.cat([p, n], 0).T * _SCALE
                loss = F.cross_entropy(
                    scores, torch.arange(len(a), device=device)
                )
                opt.zero_grad()
                loss.backward()
                opt.step()
                _after_step(loss)

    out_dir = Path(out_dir)
    _save_adapter(model, lconf, model_name, out_dir)
    return out_dir


def eval_clusters(
    adapter_dir: Path,
    rows: list[dict],
    threshold: float = 0.25,
    device: str = "mps",
) -> dict:
    """Encode rows with base vs adapted model, cluster each, report ARI
    against graph communities as ground truth."""
    import torch
    from sentence_transformers import SentenceTransformer
    from peft import PeftModel
    from sklearn.metrics import adjusted_rand_score

    from .cluster import cluster_functions, graph_communities
    from .embed import build_embed_text
    from .models import FunctionRecord

    model_name = (Path(adapter_dir) / "base_model.txt").read_text().strip()
    texts = [
        build_embed_text(FunctionRecord(**{
            k: r[k] for k in (
                "binary_sha256", "binary_name", "address", "name",
                "signature", "decompiled", "callees", "callers",
                "strings", "is_external", "is_thunk", "size",
            )
        }))
        for r in rows
    ]

    def labels_of(vecs):
        rs = [{**r, "vector": v} for r, v in zip(rows, vecs)]
        groups = cluster_functions(rs, threshold)
        lab = {}
        for gi, g in enumerate(groups):
            for m in g:
                lab[m["name"]] = gi
        return [lab[r["name"]] for r in rows]

    truth_groups = graph_communities(rows)
    truth_map = {}
    for gi, g in enumerate(truth_groups):
        for m in g:
            truth_map[m["name"]] = gi
    truth = [truth_map[r["name"]] for r in rows]

    model = SentenceTransformer(
        model_name, trust_remote_code=False, device=device
    )
    _force_bidirectional(model[0].auto_model)
    if device == "mps":
        model = model.to(torch.bfloat16)
    base_vecs = model.encode(
        texts, normalize_embeddings=True, show_progress_bar=False,
        batch_size=4,
    )

    model[0].auto_model = PeftModel.from_pretrained(
        model[0].auto_model, adapter_dir
    )
    if device == "mps":
        model = model.to(torch.bfloat16)
    ft_vecs = model.encode(
        texts, normalize_embeddings=True, show_progress_bar=False,
        batch_size=4,
    )

    return {
        "ari_base": adjusted_rand_score(truth, labels_of(base_vecs)),
        "ari_finetuned": adjusted_rand_score(truth, labels_of(ft_vecs)),
        "n_functions": len(rows),
    }
