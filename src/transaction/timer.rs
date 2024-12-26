use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
    time::Instant,
};

#[derive(Debug, PartialOrd, PartialEq, Eq, Clone)]
struct TimerKey {
    task_id: u64,
    execute_at: Instant,
}

impl Ord for TimerKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.execute_at.cmp(&other.execute_at)
    }
}

pub(super) struct Timer<T> {
    tasks: RwLock<BTreeMap<TimerKey, T>>,
    id_to_tasks: RwLock<HashMap<u64, Instant>>,
    last_task_id: AtomicU64,
}

impl<T> Timer<T> {
    pub fn new() -> Self {
        Timer {
            tasks: RwLock::new(BTreeMap::new()),
            id_to_tasks: RwLock::new(HashMap::new()),
            last_task_id: AtomicU64::new(1),
        }
    }

    pub fn timeout_at(&self, execute_at: Instant, value: T) -> u64 {
        let task_id = self.last_task_id.fetch_add(1, Ordering::Relaxed);
        self.tasks.write().unwrap().insert(
            TimerKey {
                task_id,
                execute_at,
            },
            value,
        );

        self.id_to_tasks
            .write()
            .unwrap()
            .insert(task_id, execute_at);
        task_id
    }

    pub fn cancel(&self, task_id: u64) -> Option<T> {
        self.id_to_tasks
            .write()
            .unwrap()
            .remove(&task_id)
            .and_then(|execute_at| {
                let position = TimerKey {
                    task_id,
                    execute_at,
                };
                self.tasks.write().unwrap().remove(&position)
            })
    }

    pub fn poll(&self, now: Instant) -> Vec<T> {
        let mut result = Vec::new();
        let mut tasks = self.tasks.write().unwrap();

        let keys_to_remove: Vec<_> = tasks
            .iter()
            .take_while(|(key, _)| key.execute_at <= now)
            .map(|(key, _)| key.clone())
            .collect();
        let mut id_to_tasks = self.id_to_tasks.write().unwrap();

        for key in keys_to_remove {
            id_to_tasks.remove(&key.task_id);
            result.extend(tasks.remove(&key));
        }
        result
    }
}

#[test]
fn test_timer() {
    use std::time::Duration;
    let timer = Timer::new();
    let now = Instant::now();
    let task_id = timer.timeout_at(now, "task1");
    assert_eq!(timer.cancel(task_id), Some("task1"));
    assert_eq!(timer.cancel(task_id), None);

    timer.timeout_at(now, "task2");
    let must_hass_task_2 = timer.poll(now + Duration::from_secs(1));
    assert_eq!(must_hass_task_2.len(), 1);

    timer.timeout_at(now + Duration::from_secs(3), "task3");
    let non_tasks = timer.poll(now + Duration::from_secs(1));
    assert_eq!(non_tasks.len(), 0);
}