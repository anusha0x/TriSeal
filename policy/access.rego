package triseal.authz

default allow = false
default reason = "Default deny policy"

# Route Authorization Rules
allowed_routes = {
    "red": ["arbiter:v1/gateway/prompt"],
    "arbiter": ["blue:v1/inspect/input", "llm:v1/chat/completions", "blue:v1/inspect/output"],
    "blue": ["arbiter:v1/response"],
}

# Allow if route is valid and token is authorized
allow {
    valid_route
    valid_token
}

# Route check
valid_route {
    actor := input.actor
    dest := input.destination
    allowed_routes[actor][_] == dest
}

# Token check
valid_token {
    input.token.valid == true
    input.token.budget > 0
    token_has_scope("execute_prompt")
}

token_has_scope(required_scope) {
    input.token.scope[_] == required_scope
}

# Reason reporting
reason = "Route not allowed for actor" {
    not valid_route
}

reason = "Exceeded query budget or token expired" {
    valid_route
    not valid_token
}

reason = "Access granted" {
    allow
}
