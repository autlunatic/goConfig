# goConfig
simple config file with encryption for go
Example:
    s ... somestruct
    rw... some ReadWriter

    rw := ConfigReadWriter{&s, &rw, "encrypting password"}
	err := rw.DoRead()
