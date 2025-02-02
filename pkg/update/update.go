// pkg\update\update.go
package update

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Seus arrays e constantes:
var FILES = []string{
	"metadata.json",
	"wp_fingerprints.json",
	"timthumbs-v3.txt",
	"config_backups.txt",
	"db_exports.txt",
	"dynamic_finders.yml",
	"LICENSE",
	"sponsor.txt",
}

var OLD_FILES = []string{
	"wordpress.db",
	"user-agents.txt",
	"dynamic_finders_01.yml",
	"wordpresses.json",
	"plugins.json",
	"themes.json",
}

const lastUpdateFile = ".last_update"
const baseURL = "https://data.wpscan.org"

// Updater faz o papel da classe Ruby WPScan::DB::Updater
type Updater struct {
	RepoDirectory string // Diretório onde salvamos os arquivos
	// Se precisar de API Key, você pode colocar aqui, ex: APIToken string
}

// NewUpdater cria a instância do Updater, verifica se o diretório existe, é gravável etc.
func NewUpdater(repoDir string) (*Updater, error) {
	// Garante que o caminho exista
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		return nil, fmt.Errorf("não foi possível criar o diretório %s: %w", repoDir, err)
	}
	// Verifica se é gravável
	testFile := filepath.Join(repoDir, ".testwritable")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return nil, fmt.Errorf("diretório %s não é gravável: %w", repoDir, err)
	}
	os.Remove(testFile)

	updater := &Updater{RepoDirectory: repoDir}
	// Remove arquivos obsoletos
	updater.deleteOldFiles()
	return updater, nil
}

// deleteOldFiles remove os arquivos listados em OLD_FILES, se existirem.
func (u *Updater) deleteOldFiles() {
	for _, old := range OLD_FILES {
		path := filepath.Join(u.RepoDirectory, old)
		_ = os.Remove(path)
	}
}

// lastUpdate retorna a data/hora da última atualização (ou zero time se não existir/inválido)
func (u *Updater) lastUpdate() (time.Time, error) {
	path := filepath.Join(u.RepoDirectory, lastUpdateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		// Se der erro de arquivo não encontrado, retornamos time.Time vazio
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// outdated verifica se a última atualização tem mais de 5 dias.
func (u *Updater) outdated() bool {
	lu, err := u.lastUpdate()
	if err != nil {
		return true // se deu erro, consideramos desatualizado
	}
	if lu.IsZero() {
		// se não existe .last_update
		return true
	}
	// se lu < (agora - 5 dias)
	return lu.Before(time.Now().AddDate(0, 0, -5))
}

// missingFiles retorna true se algum dos arquivos de FILES não existe localmente.
func (u *Updater) missingFiles() bool {
	for _, f := range FILES {
		path := filepath.Join(u.RepoDirectory, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
	}
	return false
}

// remoteFileURL gera a URL de um arquivo (ex: https://data.wpscan.org/<filename>)
func (u *Updater) remoteFileURL(filename string) string {
	return fmt.Sprintf("%s/%s", baseURL, filename)
}

// remoteFileChecksumURL gera a URL do checksum (ex: https://data.wpscan.org/<filename>.sha512)
func (u *Updater) remoteFileChecksumURL(filename string) string {
	return fmt.Sprintf("%s/%s.sha512", baseURL, filename)
}

// localFilePath caminho do arquivo local
func (u *Updater) localFilePath(filename string) string {
	return filepath.Join(u.RepoDirectory, filename)
}

// backupFilePath caminho do backup
func (u *Updater) backupFilePath(filename string) string {
	return filepath.Join(u.RepoDirectory, filename+".back")
}

// remoteFileChecksum obtém o conteúdo do <filename>.sha512 (deveria ser o hash)
func (u *Updater) remoteFileChecksum(filename string) (string, error) {
	url := u.remoteFileChecksumURL(filename)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum status code inesperado: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// localFileChecksum calcula o SHA512 do arquivo local
func (u *Updater) localFileChecksum(filename string) (string, error) {
	path := u.localFilePath(filename)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// createBackup copia o arquivo local para o .back (se existir)
func (u *Updater) createBackup(filename string) error {
	srcPath := u.localFilePath(filename)
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return nil // não existe => não há backup a fazer
	}
	dstPath := u.backupFilePath(filename)
	return copyFile(srcPath, dstPath)
}

// restoreBackup restaura se o backup existir
func (u *Updater) restoreBackup(filename string) error {
	backupPath := u.backupFilePath(filename)
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return nil
	}
	return copyFile(backupPath, u.localFilePath(filename))
}

// deleteBackup remove o arquivo backup
func (u *Updater) deleteBackup(filename string) error {
	backupPath := u.backupFilePath(filename)
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(backupPath)
}

// download baixa o arquivo <filename> e salva localmente
func (u *Updater) download(filename string) (string, error) {
	url := u.remoteFileURL(filename)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download status code inesperado: %d", resp.StatusCode)
	}
	localPath := u.localFilePath(filename)
	out, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", err
	}
	// Retorna o checksum do arquivo baixado
	return u.localFileChecksum(filename)
}

// update realiza o processo de atualização dos arquivos.
// Retorna uma lista de arquivos que foram atualizados.
func (u *Updater) update() ([]string, error) {
	var updated []string

	for _, filename := range FILES {
		// 1) Pega o checksum remoto
		remoteChksum, err := u.remoteFileChecksum(filename)
		if err != nil {
			// Em Ruby, lançaria erro; em Go retornamos err
			return updated, fmt.Errorf("erro ao obter checksum remoto de %s: %w", filename, err)
		}

		// 2) Verifica se existe local e se o checksum é igual
		localPath := u.localFilePath(filename)
		localExists := false
		localChksum := ""
		if _, err := os.Stat(localPath); err == nil {
			localExists = true
			localChksum, err = u.localFileChecksum(filename)
			if err != nil {
				return updated, fmt.Errorf("erro ao obter checksum local de %s: %w", filename, err)
			}
		}

		if localExists && localChksum == remoteChksum {
			// Já está atualizado
			continue
		}

		// Precisamos atualizar
		if err := u.createBackup(filename); err != nil {
			return updated, fmt.Errorf("erro ao criar backup de %s: %w", filename, err)
		}

		downloadedChksum, err := u.download(filename)
		if err != nil {
			// Se der erro no download, restaura backup
			_ = u.restoreBackup(filename)
			return updated, fmt.Errorf("erro no download de %s: %w", filename, err)
		}

		// Compara checksums
		if downloadedChksum != remoteChksum {
			// Restaura e avisa
			_ = u.restoreBackup(filename)
			return updated, fmt.Errorf("checksums não batem p/ %s (local:%s remoto:%s)", filename, downloadedChksum, remoteChksum)
		}

		// Se deu tudo certo, remove backup e adiciona na lista de atualizados
		if err := u.deleteBackup(filename); err != nil {
			return updated, fmt.Errorf("erro ao deletar backup de %s: %w", filename, err)
		}
		updated = append(updated, filename)
	}

	// Atualiza o .last_update
	nowStr := time.Now().Format(time.RFC3339)
	err := os.WriteFile(filepath.Join(u.RepoDirectory, lastUpdateFile), []byte(nowStr), 0644)
	if err != nil {
		return updated, fmt.Errorf("erro ao atualizar '%s': %w", lastUpdateFile, err)
	}

	return updated, nil
}

// copyFile é função utilitária para copiar arquivos
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		out.Close()
		if err != nil {
			// se houve erro, remove o dst
			os.Remove(dst)
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

// BaixaDatabase é só uma função que invoca o Update caso esteja desatualizado.
func BaixaDatabase() {
	updater, err := NewUpdater("database")
	if err != nil {
		fmt.Println("Erro ao criar Updater:", err)
		return
	}

	if updater.outdated() || updater.missingFiles() {
		fmt.Println("Base de dados parece desatualizada ou incompleta. Atualizando...")
		updatedFiles, err := updater.update()
		if err != nil {
			fmt.Println("Erro na atualização:", err)
			return
		}
		if len(updatedFiles) == 0 {
			fmt.Println("Nenhum arquivo precisava ser atualizado (já estava tudo ok).")
		} else {
			fmt.Println("Arquivos atualizados:", updatedFiles)
		}
	} else {
		fmt.Println("Base de dados já está atualizada (não é necessário baixar).")
	}
}
