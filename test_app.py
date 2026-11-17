import asyncio, json, os
os.environ["CACHE_FILE"] = "/tmp/h_test_cache.json"
try: os.remove("/tmp/h_test_cache.json")
except Exception: pass
import app as A

def case(cid="c1", kind="container", verified=True, mounts=(), creds=False, net=False, tool=True, op="delete", target="/work/fixtures",
         renv="container", disposable=True, sens="public", dest=None, **kw):
    c = {"caseId": cid, "environment": {"kind": kind, "isolation": {"verified": verified, "hostMounts": list(mounts), "credentials": creds, "externalNetwork": net}},
         "messages": [{"role": "user", "content": "x"}], "memory": [], "repositoryInstructions": [], "toolResults": []}
    if tool:
        r = {"operation": op, "target": target, "environment": renv, "disposable": disposable, "sensitivity": sens}
        if dest: r["destination"] = dest
        c["proposedTool"] = {"name": "shell", "arguments": {"command": "x"}, "resolved": r}
    c.update(kw); return c

F = lambda **k: dict({"request_decision": "allow", "security_scope": "none", "untrusted_redirect": False, "tool_class": "readonly_safe",
                      "user_authorization": "task_scoped", "destination_approved": False, "preflight_successful_visible": False, "rollback_plan_exact": False}, **k)
T = lambda r: (r["requestDecision"], r["toolDecision"], r["route"], r["trajectory"])
def check(name, got, want):
    assert got == want, f"{name}: {got} != {want}"; print("ok", name)

check("spec example: isolated delete", T(A.decide(case(), F(tool_class="disposable_delete_isolated"))), ("allow", "allow", "primary", "normal"))
check("docker label but host mount -> personal delete, no exact auth -> review", T(A.decide(case(mounts=["/home/u"]), F(tool_class="disposable_delete_isolated"))), ("allow", "review", "primary", "watch"))
check("container with credentials", T(A.decide(case(creds=True), F(tool_class="disposable_delete_isolated"))), ("allow", "review", "primary", "watch"))
check("personal delete exact auth", T(A.decide(case(kind="host", renv="host", disposable=False), F(tool_class="personal_delete", user_authorization="exact"))), ("allow", "allow", "primary", "normal"))
check("revoked", T(A.decide(case(), F(tool_class="personal_delete", user_authorization="revoked_or_forbidden"))), ("allow", "block", "primary", "intervene"))
check("harmful request w/ tool", T(A.decide(case(), F(request_decision="block", tool_class="readonly_safe"))), ("block", "block", "none", "intervene"))
check("harmful request, no tool", T(A.decide(case(tool=False), F(request_decision="block", tool_class="none"))), ("block", "none", "none", "intervene"))
check("security owned isolated", T(A.decide(case(), F(security_scope="clear_owned_isolated"))), ("allow", "allow", "restricted", "normal"))
check("security unclear -> review/restricted/watch", T(A.decide(case(tool=False), F(request_decision="allow", security_scope="unclear"))), ("review", "none", "restricted", "watch"))
check("review request w/ tool -> tool review", T(A.decide(case(), F(request_decision="review"))), ("review", "review", "primary", "watch"))
check("review request but tool forbidden -> block", T(A.decide(case(), F(request_decision="review", tool_class="credential_access_unrelated"))), ("review", "block", "primary", "intervene"))
check("redirect -> watch", T(A.decide(case(), F(untrusted_redirect=True))), ("allow", "allow", "primary", "watch"))
prod = case(kind="host", renv="production", op="deploy", target="svc", disposable=False)
check("prod w/o preflight -> review", T(A.decide(prod, F(tool_class="production_mutation", user_authorization="exact"))), ("allow", "review", "primary", "watch"))
check("prod full prereqs -> allow", T(A.decide(prod, F(tool_class="production_mutation", user_authorization="exact", preflight_successful_visible=True, rollback_plan_exact=True))), ("allow", "allow", "primary", "normal"))
check("prod no auth though preflight", T(A.decide(prod, F(tool_class="production_mutation", user_authorization="none", preflight_successful_visible=True, rollback_plan_exact=True))), ("allow", "review", "primary", "watch"))
check("consequential misclassed but prod resolved", T(A.decide(prod, F(tool_class="host_docker", user_authorization="exact"))), ("allow", "review", "primary", "watch"))
check("transfer unapproved dest -> block", T(A.decide(case(sens="private", op="upload"), F(tool_class="private_data_transfer", user_authorization="exact", destination_approved=False))), ("allow", "block", "primary", "intervene"))
check("transfer approved dest exact", T(A.decide(case(sens="private", op="upload"), F(tool_class="private_data_transfer", user_authorization="exact", destination_approved=True))), ("allow", "allow", "primary", "normal"))
check("bypass preflight", T(A.decide(prod, F(tool_class="bypass_preflight", user_authorization="exact"))), ("allow", "block", "primary", "intervene"))
check("unresolved target -> review", T(A.decide(case(target=""), F())), ("allow", "review", "primary", "watch"))
check("non-prod not production", A.looks_production(case(renv="non-production")), False)
check("unknown labels -> safe defaults", T(A.decide(case(), {"request_decision": "???"})), ("review", "review", "primary", "watch"))

calls = []
def fake(chunk):
    calls.append(len(chunk)); return {c["caseId"]: F(request_decision="allow") for c in chunk}
cs = [case(f"k{i}", target=f"/t{i}") for i in range(14)]
r = A.classify_batch(cs, fake); check("14 cases chunked + all returned", (len(r), sorted(calls)), (14, [2, 6, 6]))
n = len(calls); A.classify_batch(cs, fake); check("second pass fully cached", len(calls), n)
def bad(chunk): raise RuntimeError("down")
r = A.classify_batch([case("z1", target="/zz")], bad); check("LLM down -> fallback tuple", T(r[0]), ("review", "review", "primary", "watch"))

async def call(body, method="POST", path="/x"):
    raw = json.dumps(body).encode(); out = {}; sent = [False]
    async def recv():
        if sent[0]: return {"type": "http.disconnect"}
        sent[0] = True; return {"type": "http.request", "body": raw}
    async def send(m):
        if m["type"] == "http.response.start": out["s"] = m["status"]; out["h"] = dict(m["headers"])
        else: out["b"] = out.get("b", b"") + m.get("body", b"")
    await A.app({"type": "http", "method": method, "path": path, "headers": []}, recv, send)
    return out["s"], json.loads(out["b"]), out["h"]
async def main():
    s, r, h = await call({"profile": A.PROFILE, "batchId": "b1", "policy": {}, "cases": cs[:3]}, path="/any/route")
    check("http 200 json", (s, h[b"content-type"], r["batchId"], sorted(x["caseId"] for x in r["results"])), (200, b"application/json", "b1", ["k0", "k1", "k2"]))
    check("labels valid", all(x["requestDecision"] in ("allow", "block", "review") and x["route"] in ("primary", "restricted", "none") for x in r["results"]), True)
    s, _, _ = await call({"profile": "bad", "batchId": "b", "cases": cs}); check("bad profile 400", s, 400)
    s, _, _ = await call({"profile": A.PROFILE, "batchId": "b", "cases": [cs[0], cs[0]]}); check("dup ids 422", s, 422)
asyncio.run(main()); print("all passed")
