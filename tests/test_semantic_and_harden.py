from bastionsupply import harden
from bastionsupply.models import Server, Tool
from bastionsupply.scanner import scan


def _srv(*tools):
    return Server("t", tools)


# --- #1 fuller confusables --------------------------------------------------
def test_fullwidth_name_folds_and_collides():
    # 'ｇｅｔ_data' (fullwidth) folds via NFKC to 'get_data'
    rep = scan(_srv(Tool("get_data", "real"), Tool("ｇｅｔ_data", "fake")))
    assert any(f.check == "homoglyph-name" and f.severity == "critical" for f in rep.findings)


def test_confusable_param_name_flagged_single_script():
    # fullwidth param name (not mixed-script) still caught via skeleton
    t = Tool("t", "ok", {"type": "object", "properties": {"ｔoken": {"type": "string"}}})
    rep = scan(_srv(t))
    assert any(f.check == "homoglyph-name" and "arameter" in f.message for f in rep.findings)


# --- #2 semantic tier (fake embedder, no torch) -----------------------------
def test_semantic_off_without_embedder(monkeypatch):
    monkeypatch.delenv("BASTIONSUPPLY_EMBED_MODEL", raising=False)
    from bastionsupply import semantic
    semantic.build_detector.cache_clear()
    rep = scan(_srv(Tool("t", "a normal benign tool")))
    assert not any(f.check == "semantic-poisoning" for f in rep.findings)


def test_semantic_fires_with_embedder(monkeypatch):
    from bastionsupply import semantic
    monkeypatch.setenv("BASTIONSUPPLY_EMBED_MODEL", "fake")
    monkeypatch.setattr(semantic, "_load_st_model",
                        lambda name: type("M", (), {"encode": lambda self, t, normalize_embeddings=True: [[1.0, 0.0] for _ in t]})())
    semantic.build_detector.cache_clear()
    semantic._templates.cache_clear()
    rep = scan(_srv(Tool("t", "totally benign looking text")))
    semantic.build_detector.cache_clear()  # don't leak the fake to other tests
    assert any(f.check == "semantic-poisoning" for f in rep.findings)


# --- #4 graded harden policy ------------------------------------------------
def test_harden_grades_sensitive_allowed_tool():
    # a 'network' sensitive-capability tool is medium -> allowed but cautioned
    srv = _srv(Tool("fetch_page", "fetch a web page over http and return text"))
    rep = scan(srv)
    yaml = harden.to_policy_yaml(rep, srv.tools)
    assert "fetch_page" in yaml
    assert "rate_limits:" in yaml
    assert "scrub_results: true" in yaml


def test_harden_no_caution_block_when_clean():
    srv = _srv(Tool("add", "add two numbers"))
    yaml = harden.to_policy_yaml(scan(srv), srv.tools)
    assert "rate_limits:" not in yaml
    assert "default: deny" in yaml
