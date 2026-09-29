# Real-source A2A agent cards

Benign cards used as a false-positive golden (`tests/test_a2a.py`): scanning them must
produce no finding above `low`.

- `helloworld.json`: A2A Python tutorial, "Agent skills and AgentCard"
  (a2a-protocol.org/latest/tutorials/python/3-agent-skills-and-card/), rendered as JSON.
- `currency-agent.json`: a2aproject/a2a-samples, samples/python/agents/langgraph/app/__main__.py,
  rendered as JSON with the default `localhost:10000` host.
- `georoute-agent.json`: A2A specification, section 8.5 example card (skills omitted in the
  published excerpt).
