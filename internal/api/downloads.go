package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/msaif95/opamp-backend/internal/opampctldoc"
)

// cliPlatform matches the platform part of a file such as opampctl_linux_amd64 or opampctl_windows_amd64.exe.
var cliPlatform = regexp.MustCompile(`^[a-z0-9]+_[a-z0-9]+$`)

// cliBuild is one opampctl binary available for download.
type cliBuild struct {
	Platform string `json:"platform"`
	File     string `json:"file"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// cliBuilds caches the checksums of the binaries in a directory; they are read once.
type cliBuilds struct {
	once   sync.Once
	builds []cliBuild
}

func (c *cliBuilds) list(dir string) []cliBuild {
	c.once.Do(func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			platform, ok := strings.CutPrefix(strings.TrimSuffix(e.Name(), ".exe"), "opampctl_")
			if e.IsDir() || !ok || !cliPlatform.MatchString(platform) {
				continue
			}
			f, err := os.Open(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			h := sha256.New()
			size, err := io.Copy(h, f)
			f.Close()
			if err == nil {
				c.builds = append(c.builds, cliBuild{Platform: platform, File: e.Name(), Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
			}
		}
		sort.Slice(c.builds, func(i, j int) bool { return c.builds[i].Platform < c.builds[j].Platform })
	})
	return c.builds
}

// cliInfo describes the opampctl tool shipped with this deployment: its
// usage text (the same the tool prints) and the builds that can be downloaded.
func (s *Server) cliInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Status.Version, "usage": opampctldoc.Usage, "builds": nonNil(s.cli.list(s.CLIDir))})
}

// cliDownload sends the opampctl binary for one platform.
func (s *Server) cliDownload(w http.ResponseWriter, r *http.Request) {
	platform := chi.URLParam(r, "platform")
	for _, b := range s.cli.list(s.CLIDir) {
		if b.Platform != platform {
			continue
		}
		f, err := os.Open(filepath.Join(s.CLIDir, b.File))
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			s.internal(w, r, err)
			return
		}
		defer f.Close()
		name := "opampctl"
		if strings.HasSuffix(b.File, ".exe") {
			name += ".exe"
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("X-Checksum-Sha256", b.SHA256)
		http.ServeContent(w, r, name, time.Time{}, f)
		return
	}
	writeError(w, http.StatusNotFound, "opampctl is not available for that platform from this deployment")
}
