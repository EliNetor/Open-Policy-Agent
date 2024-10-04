package barmanagement #namespace
default allow := false

import input.request.headers.Authorization

allow {
    jwt_token := extract_bearer_token(input.request.headers.Authorization)
    [jwt_header, jwt_payload, jwt_signature] := io.jwt.decode(jwt_token)
    age := to_number(jwt_payload.age)
    role := jwt_payload.role[_]
    role == "customer"
    input.request.body.DrinkName == "Beer"
    age >= 16
    input.request.path != "/api/managebar"
}

allow {
    jwt_token := extract_bearer_token(input.request.headers.Authorization)
    [jwt_header, jwt_payload, jwt_signature] := io.jwt.decode(jwt_token)
    role := jwt_payload.role[_]
    role == "customer"
    input.request.body.DrinkName != "Beer"
    input.request.path != "/api/managebar"
}

allow {
    jwt_token := extract_bearer_token(input.request.headers.Authorization)
    [jwt_header, jwt_payload, jwt_signature] := io.jwt.decode(jwt_token)
    role := jwt_payload.role[_]
    role == "bartender"
    input.request.path == "/api/managebar"
}

extract_bearer_token(auth_header) = token {
    startswith(auth_header, "Bearer ")
    token := substring(auth_header, 7, -1)
}