package utils

import (
	"io/ioutil"
	"sync"

	"gopkg.in/yaml.v2"
)

// loadDynamicFinders carrega o arquivo YAML inteiro num mapa genérico.
func LoadDynamicFinders() map[interface{}]interface{} {
	var (
		dynamicFindersMap map[interface{}]interface{}
		dfOnce            sync.Once
	)
	dfOnce.Do(func() {
		// Atenção: use o caminho e nome corretos para o arquivo YAML!
		data, err := ioutil.ReadFile("./database/dynamic_finders.yml")
		if err != nil {
			return
		}
		var m map[interface{}]interface{}
		if err := yaml.Unmarshal(data, &m); err != nil {
			return
		}
		dynamicFindersMap = m
		// (Opcional) Debug: exibe as chaves de nível superior
		// fmt.Printf("Chaves do YAML: %+v\n", dynamicFindersMap)
	})
	return dynamicFindersMap
}
