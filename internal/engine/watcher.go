package engine

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

// watchFileInternal starts an fsnotify watcher and SIGHUP handler for
// hot-reloading the rules file. Runs in a background goroutine until
// the engine is closed.
func (r *RuleEngine) watchFileInternal(path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return err
	}

	// Also listen for SIGHUP as an explicit reload trigger.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	go func() {
		defer watcher.Close()
		defer signal.Stop(sighup)

		for {
			select {
			case <-r.stopCh:
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Reload on write or create (editors often create a new file).
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					r.log.Info().Str("path", path).Msg("rules file changed, reloading")
					if err := r.LoadFromFile(path); err != nil {
						r.log.Error().Err(err).Msg("failed to reload rules")
					}
					// Re-add the watch in case the file was recreated (e.g. by vim).
					_ = watcher.Add(path)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				r.log.Error().Err(err).Msg("fsnotify error")

			case <-sighup:
				r.log.Info().Msg("SIGHUP received, reloading rules")
				if err := r.LoadFromFile(path); err != nil {
					r.log.Error().Err(err).Msg("failed to reload rules on SIGHUP")
				}
			}
		}
	}()

	r.log.Info().Str("path", path).Msg("watching rules file for changes")
	return nil
}
