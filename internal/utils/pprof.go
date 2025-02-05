package utils

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricRow representa uma linha da tabela com os dados de uma métrica.
type MetricRow struct {
	Name        string
	Labels      string
	Type        string
	Value       float64
	Explanation string
}

// Map de explicações para algumas métricas conhecidas.
// Você pode adicionar quantas explicações achar necessário.
var explanations = map[string]string{
	"go_gc_duration_seconds":                 "Duração (em segundos) das pausas da coleta de lixo.",
	"go_gc_gogc_percent":                     "Percentual de tamanho de heap configurado (GOGC).",
	"go_gc_gomemlimit_bytes":                 "Limite de memória configurado para o Go (GOMEMLIMIT).",
	"go_goroutines":                          "Número de goroutines atualmente em execução.",
	"go_info":                                "Informações sobre o ambiente Go.",
	"go_memstats_alloc_bytes":                "Bytes atualmente alocados na heap.",
	"go_memstats_alloc_bytes_total":          "Total de bytes alocados na heap até agora.",
	"go_memstats_buck_hash_sys_bytes":        "Bytes usados pela tabela de hash de profiling.",
	"go_memstats_frees_total":                "Número total de frees de objetos da heap.",
	"go_memstats_gc_sys_bytes":               "Bytes usados para metadados do garbage collector.",
	"go_memstats_heap_alloc_bytes":           "Bytes alocados na heap atualmente.",
	"go_memstats_heap_idle_bytes":            "Bytes da heap inativos (livres).",
	"go_memstats_heap_inuse_bytes":           "Bytes da heap em uso.",
	"go_memstats_heap_objects":               "Número de objetos atualmente alocados na heap.",
	"go_memstats_heap_released_bytes":        "Bytes da heap liberados para o sistema.",
	"go_memstats_heap_sys_bytes":             "Bytes obtidos do sistema para a heap.",
	"go_memstats_last_gc_time_seconds":       "Timestamp do último garbage collection.",
	"go_memstats_mallocs_total":              "Número total de mallocs na heap.",
	"go_memstats_mcache_inuse_bytes":         "Bytes em uso pelas estruturas mcache.",
	"go_memstats_mcache_sys_bytes":           "Bytes obtidos do sistema para mcache.",
	"go_memstats_mspan_inuse_bytes":          "Bytes em uso pelas estruturas mspan.",
	"go_memstats_mspan_sys_bytes":            "Bytes obtidos do sistema para mspan.",
	"go_memstats_next_gc_bytes":              "Tamanho da heap para que ocorra a próxima coleta de lixo.",
	"go_memstats_other_sys_bytes":            "Bytes usados para outras alocações do sistema.",
	"go_memstats_stack_inuse_bytes":          "Bytes obtidos para o stack do processo.",
	"go_memstats_stack_sys_bytes":            "Bytes obtidos do sistema para o stack.",
	"go_memstats_sys_bytes":                  "Bytes totais obtidos do sistema.",
	"go_sched_gomaxprocs_threads":            "Valor de GOMAXPROCS (threads que podem executar código Go simultaneamente).",
	"go_threads":                             "Número de threads do sistema criadas.",
	"process_cpu_seconds_total":              "Tempo total de CPU (em segundos) usado pelo processo.",
	"process_max_fds":                        "Número máximo de file descriptors abertos.",
	"process_open_fds":                       "Número de file descriptors abertos atualmente.",
	"process_resident_memory_bytes":          "Memória residente do processo (em bytes).",
	"process_start_time_seconds":             "Timestamp do início do processo.",
	"process_virtual_memory_bytes":           "Memória virtual do processo (em bytes).",
	"promhttp_metric_handler_requests_total": "Total de scrapes realizados pelo handler do Prometheus.",
	// Adicione outras métricas conforme necessário...
}

// dashboardHandler coleta as métricas via DefaultGatherer, processa e renderiza uma tabela.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		http.Error(w, "Erro ao coletar métricas: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var rows []MetricRow
	// Percorre todas as metric families
	for _, mf := range mfs {
		metricName := *mf.Name
		metricType := mf.GetType().String()
		explanation := explanations[metricName]
		if explanation == "" {
			explanation = "Sem explicação disponível."
		}
		// Para cada métrica (podendo haver várias instâncias com labels)
		for _, m := range mf.Metric {
			labels := []string{}
			for _, lp := range m.Label {
				labels = append(labels, fmt.Sprintf("%s=%q", *lp.Name, *lp.Value))
			}
			labelsStr := strings.Join(labels, " ")

			var value float64
			switch metricType {
			case "GAUGE":
				value = m.GetGauge().GetValue()
			case "COUNTER":
				value = m.GetCounter().GetValue()
			case "SUMMARY":
				// Para sumários, podemos usar o somatório
				value = m.GetSummary().GetSampleSum()
			case "UNTYPED":
				value = m.GetUntyped().GetValue()
			default:
				value = 0
			}

			rows = append(rows, MetricRow{
				Name:        metricName,
				Labels:      labelsStr,
				Type:        metricType,
				Value:       value,
				Explanation: explanation,
			})
		}
	}

	// Template HTML para exibir a tabela de métricas com Bootstrap.
	const tpl = `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Dashboard de Métricas</title>
	<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
	<style>
		body { padding-top: 20px; }
		.table td, .table th { vertical-align: middle; }
	</style>
</head>
<body>
	<div class="container">
		<h1 class="mb-4">Dashboard de Métricas da Aplicação</h1>
		<p class="lead">Esta página exibe as métricas do Prometheus de forma explicativa e visual.</p>
		<table class="table table-bordered table-striped">
			<thead class="thead-dark">
				<tr>
					<th>Métrica</th>
					<th>Tipo</th>
					<th>Valor</th>
					<th>Labels</th>
					<th>Explicação</th>
				</tr>
			</thead>
			<tbody>
				{{range .}}
				<tr>
					<td>{{.Name}}</td>
					<td>{{.Type}}</td>
					<td>{{printf "%.2f" .Value}}</td>
					<td>{{.Labels}}</td>
					<td>{{.Explanation}}</td>
				</tr>
				{{end}}
			</tbody>
		</table>
		<div class="mt-3">
			<a href="/metrics" class="btn btn-secondary">Ver Métricas Brutas (/metrics)</a>
		</div>
	</div>
</body>
</html>`

	tmpl := template.Must(template.New("dashboard").Parse(tpl))
	if err := tmpl.Execute(w, rows); err != nil {
		http.Error(w, fmt.Sprintf("Erro ao renderizar template: %v", err), http.StatusInternalServerError)
	}
}

// InitPrometheusDashboard registra os endpoints e inicia o servidor na porta 6060.
// Endpoints:
//   - "/"        -> dashboard visual com a tabela de métricas e explicações
//   - "/metrics" -> endpoint padrão para o Prometheus realizar o scrape
func InitPrometheusDashboard() {
	http.HandleFunc("/", dashboardHandler)
	http.Handle("/metrics", promhttp.Handler())

	fmt.Println("Dashboard iniciado em http://localhost:6060/")
	fmt.Println("Métricas Prometheus: http://localhost:6060/metrics")

	// Inicia o servidor em uma goroutine para que a execução continue
	go func() {
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			fmt.Printf("Erro ao iniciar o servidor: %v\n", err)
		}
	}()
}
