use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Condvar, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use tokio::sync::Notify;

#[derive(Debug, PartialEq, Eq, Clone)]
struct TimerKey {
    task_id: u64,
    execute_at: Instant,
}

impl Ord for TimerKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.execute_at
            .cmp(&other.execute_at)
            .then_with(|| self.task_id.cmp(&other.task_id))
    }
}

impl PartialOrd for TimerKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct Timer<T> {
    state: Mutex<TimerState<T>>,
    condvar: Condvar,
    notify: Notify,
    last_task_id: AtomicU64,
}

impl<T> Timer<T> {
    pub fn new() -> Self {
        Timer {
            state: Mutex::new(TimerState::new()),
            condvar: Condvar::new(),
            notify: Notify::new(),
            last_task_id: AtomicU64::new(1),
        }
    }

    pub fn len(&self) -> usize {
        self.lock_state().tasks.len()
    }

    pub fn timeout(&self, duration: Duration, value: T) -> u64 {
        self.timeout_at(Instant::now() + duration, value)
    }

    pub fn timeout_at(&self, execute_at: Instant, value: T) -> u64 {
        let task_id = self.last_task_id.fetch_add(1, Ordering::Relaxed);
        let mut state = self.lock_state();
        let key = TimerKey {
            task_id,
            execute_at,
        };
        let should_notify = match state.tasks.keys().next() {
            Some(head) => key < head.clone(),
            None => true,
        };

        state.tasks.insert(key.clone(), value);
        state.id_to_tasks.insert(task_id, execute_at);
        drop(state);

        if should_notify {
            self.condvar.notify_all();
            self.notify.notify_waiters();
        } else {
            self.condvar.notify_one();
            self.notify.notify_one();
        }
        task_id
    }

    pub fn cancel(&self, task_id: u64) -> Option<T> {
        let mut state = self.lock_state();
        let execute_at = match state.id_to_tasks.remove(&task_id) {
            Some(execute_at) => execute_at,
            None => return None,
        };

        let key = TimerKey {
            task_id,
            execute_at,
        };

        let was_head = state
            .tasks
            .iter()
            .next()
            .map(|(head, _)| head == &key)
            .unwrap_or(false);

        let removed = state.tasks.remove(&key);
        drop(state);

        if removed.is_some() {
            if was_head {
                self.condvar.notify_all();
                self.notify.notify_waiters();
            } else {
                self.condvar.notify_one();
                self.notify.notify_one();
            }
        }

        removed
    }

    pub fn poll(&self, now: Instant) -> Vec<T> {
        let mut state = self.lock_state();
        Self::collect_ready(&mut state, now)
    }

    pub async fn wait_for_ready(&self) -> Vec<T> {
        loop {
            let (ready, next_deadline) = {
                let mut state = self.lock_state();
                let now = Instant::now();
                let ready = Self::collect_ready(&mut state, now);
                let next_deadline = if ready.is_empty() {
                    state.tasks.keys().next().map(|key| key.execute_at)
                } else {
                    None
                };
                (ready, next_deadline)
            };

            if !ready.is_empty() {
                return ready;
            }

            match next_deadline {
                Some(deadline) => {
                    let now = Instant::now();
                    let wait_duration = deadline.checked_duration_since(now).unwrap_or_default();

                    tokio::select! {
                        _ = tokio::time::sleep(wait_duration) => {},
                        _ = self.notify.notified() => {},
                    }
                }
                None => {
                    self.notify.notified().await;
                }
            }
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.lock_state()
            .tasks
            .iter()
            .next()
            .map(|(key, _)| key.execute_at)
    }
}

#[test]
fn test_timer() {
    use std::time::Duration;
    let timer = Timer::new();
    let now = Instant::now();
    let task_id = timer.timeout_at(now, "task1");
    assert_eq!(task_id, 1);
    assert_eq!(timer.cancel(task_id), Some("task1"));
    assert_eq!(timer.cancel(task_id), None);

    timer.timeout_at(now, "task2");
    let must_hass_task_2 = timer.poll(now + Duration::from_secs(1));
    assert_eq!(must_hass_task_2.len(), 1);

    timer.timeout_at(now + Duration::from_millis(1001), "task3");
    let non_tasks = timer.poll(now + Duration::from_secs(1));
    assert_eq!(non_tasks.len(), 0);
    assert_eq!(timer.len(), 1);
}

#[tokio::test]
async fn wait_for_ready_async_returns_ready() {
    let timer = Timer::new();
    timer.timeout(Duration::from_millis(50), "ready");

    let ready = tokio::time::timeout(Duration::from_secs(1), timer.wait_for_ready())
        .await
        .expect("wait_for_ready_async timed out");
    assert_eq!(ready, vec!["ready"]);
}

#[tokio::test]
async fn wait_for_ready_async_wakes_on_new_timer() {
    use std::sync::Arc;

    let timer = Arc::new(Timer::new());
    timer.timeout(Duration::from_secs(5), "late");

    let worker = Arc::clone(&timer);
    let wait_handle = tokio::spawn(async move { worker.wait_for_ready().await });

    tokio::time::sleep(Duration::from_millis(100)).await;
    timer.timeout(Duration::from_millis(200), "early");

    let ready = tokio::time::timeout(Duration::from_secs(2), wait_handle)
        .await
        .expect("wait_for_ready_async task timed out")
        .expect("wait_for_ready_async task panicked");

    assert_eq!(ready, vec!["early"]);
}

impl<T> Timer<T> {
    fn lock_state(&self) -> MutexGuard<'_, TimerState<T>> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn collect_ready(state: &mut TimerState<T>, now: Instant) -> Vec<T> {
        let mut ready = Vec::new();

        while let Some(key) = state.tasks.keys().next().cloned() {
            if key.execute_at > now {
                break;
            }

            if let Some(value) = state.tasks.remove(&key) {
                state.id_to_tasks.remove(&key.task_id);
                ready.push(value);
            }
        }

        ready
    }
}

struct TimerState<T> {
    tasks: BTreeMap<TimerKey, T>,
    id_to_tasks: HashMap<u64, Instant>,
}

impl<T> TimerState<T> {
    fn new() -> Self {
        Self {
            tasks: BTreeMap::new(),
            id_to_tasks: HashMap::new(),
        }
    }
}
