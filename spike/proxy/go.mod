module proxyelk/spike/proxy

go 1.23

// Épinglé explicitement : les versions plus récentes (v3.4.9+) exigent un
// compilateur Go plus récent que golang:1.23-alpine (voir proxy/Dockerfile).
require github.com/go-ldap/ldap/v3 v3.4.8
