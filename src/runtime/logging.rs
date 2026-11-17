//! A slow diagnostic sink must not park the network runtime.
use std::{io::Write, sync::OnceLock};
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};

pub const BUFFERED_RECORDS: usize = 256;
static DROPPED: OnceLock<ErrorCounter> = OnceLock::new();

fn writer<W: Write + Send + 'static>(sink: W, capacity: usize) -> (NonBlocking, WorkerGuard) {
    NonBlockingBuilder::default()
        .buffered_lines_limit(capacity)
        .lossy(true)
        .thread_name("braidpath-log")
        .finish(sink)
}

/// Keep the guard until CLI shutdown so ordinary final records are flushed.
pub fn stderr() -> (NonBlocking, WorkerGuard) {
    let (writer, guard) = writer(std::io::stderr(), BUFFERED_RECORDS);
    let _ = DROPPED.set(writer.error_counter());
    (writer, guard)
}

pub fn dropped_records() -> usize {
    DROPPED.get().map_or(0, ErrorCounter::dropped_lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct Gate(Arc<(Mutex<(bool, bool)>, Condvar)>);
    impl Gate {
        fn release(&self) {
            let (state, ready) = &*self.0;
            state.lock().unwrap().1 = true;
            ready.notify_all();
        }
    }
    impl Write for Gate {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let (state, ready) = &*self.0;
            let mut state = state.lock().unwrap();
            state.0 = true;
            ready.notify_all();
            while !state.1 {
                state = ready.wait(state).unwrap();
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct Release(Gate);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[test]
    fn blocked_sink_and_full_queue_do_not_block_the_producer() {
        let gate = Gate::default();
        let (mut log, guard) = writer(gate.clone(), 2);
        // Unblock the worker even when an assertion fails.
        let _release = Release(gate.clone());
        log.write_all(b"first\n").unwrap();
        let (state, ready) = &*gate.0;
        let (state, _) = ready
            .wait_timeout_while(state.lock().unwrap(), Duration::from_secs(2), |s| !s.0)
            .unwrap();
        let entered = state.0;
        drop(state);
        assert!(entered, "log worker reached the blocked sink");
        let errors = log.error_counter();
        let (done, result) = mpsc::channel();
        let producer = std::thread::spawn(move || {
            for _ in 0..16 {
                log.write_all(b"bounded\n").unwrap();
            }
            done.send(()).unwrap();
        });
        result.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(errors.dropped_lines() > 0, "overflow remains observable");
        gate.release();
        producer.join().unwrap();
        drop(guard);
    }

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn normal_shutdown_flushes_in_order() {
        let sink = Buffer::default();
        let (mut log, guard) = writer(sink.clone(), 2);
        log.write_all(b"first\n").unwrap();
        log.write_all(b"last\n").unwrap();
        drop(guard);
        assert_eq!(&*sink.0.lock().unwrap(), b"first\nlast\n");
        assert_eq!(log.error_counter().dropped_lines(), 0);
    }
}
