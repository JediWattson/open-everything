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


def train(
    pair_paths: list[Path],
    out_dir: Path,
    model_name: str,
    epochs: int = 1,
    batch_size: int = 1,
    lr: float = 2e-5,
    max_len: int = 1024,
    device: str = "mps",
    on_progress=None,
) -> Path:
    import torch
    import torch.nn.functional as F
    from torch.utils.data import DataLoader
    from sentence_transformers import SentenceTransformer
    from peft import LoraConfig, get_peft_model

    rows = load_triplets(pair_paths)
    if not rows:
        raise ValueError("no triplets loaded")

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

    loader = DataLoader(
        [InputExample(texts=r) for r in rows],
        batch_size=batch_size, shuffle=True, drop_last=True,
        collate_fn=model.smart_batching_collate,
    )
    trainable = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(trainable, lr=lr)
    steps = epochs * len(loader)

    step = 0
    for ep in range(epochs):
        for feats, _labels in loader:
            feats = [
                {
                    k: v.to(device) if isinstance(v, torch.Tensor) else v
                    for k, v in f.items()
                }
                for f in feats[:3]
            ]
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
            step += 1
            if on_progress:
                on_progress(step, steps, float(loss))

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # peft's save_pretrained dumps merged weights on this stack — emit the
    # adapter files explicitly instead.
    from safetensors.torch import save_file

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
