package utils

import (
	"fmt"
	"net/http"
	_ "net/http/pprof" // importa o pprof para registrar os endpoints
)

func InitPprof() {
	go func() {
		fmt.Println("Iniciando pprof em http://localhost:6060/debug/pprof/")
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			fmt.Printf("Erro ao iniciar pprof: %v\n", err)
		}
	}()
}
