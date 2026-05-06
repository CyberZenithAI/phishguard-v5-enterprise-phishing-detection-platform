import asyncio
from app.core.generator import generate
from app.core.resolver import resolve
from app.core.similarity import similarity
from app.core.scorer import score
from app.core.intel import enrich

async def analyze(domain):
    variants = generate(domain)

    tasks = [resolve(v) for v in variants]
    dns = await asyncio.gather(*tasks)

    results = []

    for r in dns:
        sim = similarity(domain.split('.')[0], r["domain"].split('.')[0])
        intel = await enrich(r["domain"])

        r["score"] = score(r, sim)
        r["similarity"] = sim

        results.append(r)

    return sorted(results, key=lambda x: x["score"], reverse=True)